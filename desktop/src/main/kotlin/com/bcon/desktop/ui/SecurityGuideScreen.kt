package com.subrosa.desktop

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private data class GuideItem(val title: String, val desc: String)

/** Desktop port of Android's SecurityGuideScreen.kt — same expandable-card
 *  reference, but only for features that actually exist here. Deliberately
 *  excludes the phone-coercion-specific ones (panic password, emergency
 *  wipe button, dead man's switch, timeout wipe, panic notification, wipe
 *  levels, paranoid/alert-URL spyware detection) — those all assume a
 *  device that can be physically grabbed from your hands, which isn't
 *  Desktop's threat model. Tor's description is reworded for Desktop's
 *  actual behavior (SOCKS proxy auto-detected for .onion server URLs, no
 *  Orbot/toggle involved). */
@Composable
fun SecurityGuideScreen(onBack: () -> Unit) {
    val items = remember {
        listOf(
            GuideItem(
                "Invite-код",
                "Способ анонимно познакомиться с человеком, не раскрывая серверу пару отправитель-получатель. Код одноразовый: после того как кто-то его отсканирует, зашитый в нём тег «умирает» и перестаёт работать. На устройстве в любой момент активен только один такой тег — повторное нажатие «Копировать» тоже его меняет, даже если предыдущий получатель ещё не подключился, и молча ломает его код. Добавляешь нескольких людей — дожидайся подключения текущего, прежде чем генерировать код для следующего."
            ),
            GuideItem(
                "Верификация пользователя",
                "Последовательность из 5 эмодзи, полученная из хэша публичного ключа собеседника (Меню чата → «Проверить ключ»). Сверьте её с собеседником лично или по другому каналу — если совпадает, вы точно говорите с ним, а не с кем-то, кто подменил ключ (атака «человек посередине»)."
            ),
            GuideItem(
                "Двухфакторная защита (TOTP)",
                "Обязательный код из приложения-аутентификатора (как Google Authenticator), без которого этот аккаунт нельзя зарегистрировать на новом устройстве, даже если ключи и пароль украдены. Сохраните резервные коды, выданные при настройке, отдельно от компьютера. Резервный код пускает на новое устройство, если аутентификатор потерян, но не отключает защиту сам по себе — сразу после входа настройте TOTP заново на этом устройстве (для этого понадобится ещё один резервный код)."
            ),
            GuideItem(
                "Автоблокировка",
                "Приложение блокируется паролем через заданное время бездействия. Чем короче интервал, тем меньше окно, в течение которого кто-то может подойти к разблокированному компьютеру и открыть переписку."
            ),
            GuideItem(
                "Резервное копирование",
                "Зашифрованный файл со всеми ключами и историей сообщений. Защищён паролем, а восстановление на новом устройстве дополнительно требует TOTP-секрет — одного файла и пароля к нему недостаточно. Храните файл, пароль и TOTP-секрет в разных местах."
            ),
            GuideItem(
                "Tor",
                "Если адрес сервера — .onion, приложение само обнаруживает локальный SOCKS-прокси (системный tor-демон на порту 9050 или Tor Browser на 9150) и маршрутизирует соединение через него, скрывая ваш IP-адрес от самого сервера. Никакой переключатель не нужен — достаточно, чтобы Tor уже был запущен на компьютере."
            ),
            GuideItem(
                "Постоянный трафик",
                "Приложение шлёт пакеты-пустышки через равные интервалы, даже когда вы ничего не отправляете, — так внешний наблюдатель не может по паттерну трафика понять, переписываетесь вы сейчас или нет. Расходует немного интернета."
            ),
            GuideItem(
                "Смена identity",
                "Если подозреваете, что ваш ключ украли — это полностью уничтожает текущие ключи, контакты и переписку на этом устройстве и выдаёт новые. Перед удалением приложение также сообщает серверу отозвать старую identity — старый ключ больше не сможет пройти регистрацию, даже если он попал в чужие руки. Контактам нужно будет заново обменяться с вами свежим инвайт-кодом, чтобы перейти на новую identity. Необратимо."
            ),
            GuideItem(
                "Удаление контакта",
                "Удаление контакта — не просто очистка списка. Приложение сразу отзывает у него все ещё не потраченные токены (писать вам старыми уже не получится) и блокирует новые попытки связаться с этим человеком — даже если он пришлёт новый запрос на сессию, устройство молча его проигнорирует. Блокировка снимается сама, если вы позже добавите тот же контакт заново по свежему инвайт-коду. Это быстрый способ отрезать контакта, чьё устройство вы считаете скомпрометированным."
            ),
            GuideItem(
                "Самовосстановление связи",
                "Приложение специально не раскрывает серверу, кто с кем переписывается — это сильно повышает приватность, но иногда означает, что после сбоя (например, долгого отсутствия сети) переписка или звонок восстанавливаются не мгновенно, а через какое-то время. Это не значит, что что-то сломано: канал связи умеет чиниться сам. Если сообщение не идёт — обычно достаточно подождать, или воспользоваться пунктом «Восстановить связь» в меню чата."
            )
        )
    }
    val s = LocalStrings.current
    var expandedIndex by remember { mutableStateOf<Int?>(0) }

    Column(Modifier.fillMaxSize()) {
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(AppIcons.get("BACK_ARROW"), contentDescription = s.close, tint = SubrosaTheme.textPrimary)
                }
                Text(s.profileSecurityGuide, fontSize = 19.sp, fontWeight = FontWeight.SemiBold, color = SubrosaTheme.textPrimary)
            }
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(items.size) { index ->
                val item = items[index]
                val expanded = expandedIndex == index
                Card(
                    modifier = Modifier.fillMaxWidth().animateContentSize(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = SubrosaTheme.card)
                ) {
                    Column {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { expandedIndex = if (expanded) null else index }
                                .padding(horizontal = 16.dp, vertical = 14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                item.title,
                                fontSize = 17.sp,
                                fontWeight = FontWeight.Bold,
                                color = SubrosaTheme.textPrimary,
                                modifier = Modifier.weight(1f)
                            )
                            Text(
                                if (expanded) "▲" else "▼",
                                fontSize = 13.sp,
                                color = SubrosaTheme.textSecondary
                            )
                        }
                        AnimatedVisibility(
                            visible = expanded,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut()
                        ) {
                            Text(
                                item.desc,
                                fontSize = 15.sp,
                                lineHeight = 19.sp,
                                color = SubrosaTheme.textSecondary,
                                modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}
