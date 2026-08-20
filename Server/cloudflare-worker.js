/**
 * Subrosa Messenger — Cloudflare Worker WebSocket Proxy
 *
 * Назначение:
 *   Проксирует WebSocket-соединения клиентов через Cloudflare на реальный
 *   сервер Subrosa. С точки зрения любого фаервола/белого списка — это обычный
 *   HTTPS-запрос к Cloudflare IP на порту 443.
 *
 * Деплой:
 *   1. Зарегистрируйся на https://dash.cloudflare.com → Workers & Pages → Create
 *   2. Вставь этот код в редактор
 *   3. В Settings → Variables добавь переменную:
 *        BACKEND_HOST = "your-real-server.com"   (домен/IP твоего сервера)
 *        BACKEND_PORT = "9000"                   (порт сервера, обычно 9000)
 *   4. Сохрани и задеплой
 *   5. Добавь кастомный домен (опционально) или используй *.workers.dev
 *
 * Адрес для клиентов:
 *   wss://your-worker.your-subdomain.workers.dev
 *   или
 *   wss://Subrosa.yourdomain.com  (если привязал кастомный домен)
 *
 * Важно:
 *   - Cloudflare Workers поддерживают WebSocket нативно (Durable Objects не нужны)
 *   - Бесплатный план: 100 000 запросов/день — достаточно для старта
 *   - Платный план ($5/мес): 10 млн запросов/мес
 */

export default {
    async fetch(request, env) {
        const backendHost = env.BACKEND_HOST || "localhost";
        const backendPort = env.BACKEND_PORT || "9000";

        // ── WebSocket соединение ──────────────────────────────────────────────
        const upgradeHeader = request.headers.get("Upgrade");
        if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
            return handleWebSocket(request, backendHost, backendPort);
        }

        // ── Обычный HTTP (healthcheck) ────────────────────────────────────────
        return new Response(JSON.stringify({
            status: "ok",
            service: "Subrosa Proxy",
            timestamp: Date.now()
        }), {
            headers: { "Content-Type": "application/json" }
        });
    }
};

async function handleWebSocket(request, backendHost, backendPort) {
    // Создаём пару WebSocket: один для клиента, один для бэкенда
    const { 0: clientSocket, 1: serverSocket } = new WebSocketPair();

    // Принимаем соединение от клиента
    serverSocket.accept();

    // Подключаемся к реальному серверу Subrosa
    const backendUrl = `wss://${backendHost}:${backendPort === "443" ? "" : ":" + backendPort}`;

    let backend;
    try {
        backend = new WebSocket(backendUrl);
    } catch (e) {
        return new Response("Backend unavailable", { status: 502 });
    }

    // Клиент → Бэкенд
    serverSocket.addEventListener("message", (event) => {
        if (backend.readyState === WebSocket.OPEN) {
            backend.send(event.data);
        }
    });

    // Бэкенд → Клиент
    backend.addEventListener("message", (event) => {
        if (serverSocket.readyState === WebSocket.OPEN) {
            serverSocket.send(event.data);
        }
    });

    // Закрытие клиентом
    serverSocket.addEventListener("close", (event) => {
        backend.close(event.code, event.reason);
    });

    // Закрытие бэкендом
    backend.addEventListener("close", (event) => {
        serverSocket.close(event.code, event.reason);
    });

    // Ошибка бэкенда
    backend.addEventListener("error", () => {
        serverSocket.close(1011, "Backend error");
    });

    return new Response(null, {
        status: 101,
        webSocket: clientSocket
    });
}
