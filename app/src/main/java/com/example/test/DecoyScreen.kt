package com.bcon.messenger

import androidx.activity.compose.BackHandler
import android.database.ContentObserver
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.bcon.messenger.ui.theme.LocalBeaconColors
import kotlin.math.absoluteValue

private data class FakeMsg(val text: String, val fromMe: Boolean, val time: String)

private data class ChatTemplate(
    val name: String,
    val lastTime: String,
    val unread: Int = 0,
    val messages: List<FakeMsg>
)

private val decoyAvatarPalette = listOf(
    Color(0xFF2481CC), Color(0xFFE74C3C), Color(0xFF27AE60),
    Color(0xFFF39C12), Color(0xFF9B59B6), Color(0xFF1ABC9C)
)
private fun avatarColorFor(name: String) =
    decoyAvatarPalette[name.hashCode().absoluteValue % decoyAvatarPalette.size]

private val chatPool = listOf(

    ChatTemplate("Мама", "14:32", unread = 0, listOf(
        FakeMsg("Сынок, как дела? Давно не звонил", false, "12:40"),
        FakeMsg("Хорошо мам, работы много немного", true, "13:05"),
        FakeMsg("Ты сегодня приедешь?", false, "13:06"),
        FakeMsg("Постараюсь к вечеру", true, "13:07"),
        FakeMsg("Ладно. Купи хлеба по дороге, белого", false, "14:32"),
    )),

    ChatTemplate("Мама", "11:20", unread = 1, listOf(
        FakeMsg("Ты как себя чувствуешь? Голос у тебя вчера был странный", false, "09:00"),
        FakeMsg("Нормально, просто устал немного", true, "09:45"),
        FakeMsg("Таблетки пьёшь?", false, "09:46"),
        FakeMsg("Да мам, всё пью не волнуйся", true, "09:47"),
        FakeMsg("Хорошо. Суп сварила, заедь покушай", false, "11:20"),
    )),

    ChatTemplate("Папа", "Вчера", unread = 0, listOf(
        FakeMsg("Масло когда последний раз менял на своей?", false, "17:00"),
        FakeMsg("В октябре кажется, давно уже", true, "17:20"),
        FakeMsg("Пора, уже 10к намотал наверное. Запись сделай", false, "17:21"),
        FakeMsg("Ага, на выходных займусь", true, "17:22"),
        FakeMsg("Ключи у меня в гараже, приезжай помогу", false, "17:23"),
    )),

    ChatTemplate("Антон", "14:05", unread = 2, listOf(
        FakeMsg("Бро, что вечером делаешь?", false, "12:50"),
        FakeMsg("Пока ничего, а что?", true, "13:10"),
        FakeMsg("Встретимся? Давно не виделись", false, "13:11"),
        FakeMsg("Давай, куда?", true, "13:12"),
        FakeMsg("К Серёге зайдём, он зовёт", false, "13:13"),
        FakeMsg("Ок, во сколько?", true, "13:14"),
        FakeMsg("Ок, завтра встречаемся в 19:00", false, "14:05"),
    )),

    ChatTemplate("Дима", "Вчера", unread = 0, listOf(
        FakeMsg("Смотрел матч вчера?", false, "20:00"),
        FakeMsg("Нет, пропустил. Как прошло?", true, "20:30"),
        FakeMsg("3:1, красотища! Наши разнесли их", false, "20:31"),
        FakeMsg("Серьёзно? Жаль не смотрел", true, "20:32"),
        FakeMsg("В субботу ещё игра, пойдём вместе?", false, "20:33"),
        FakeMsg("Давай, напомни за день", true, "20:34"),
    )),

    ChatTemplate("Серёга", "Вчера", unread = 1, listOf(
        FakeMsg("Заходи вечером поиграем", false, "18:00"),
        FakeMsg("Во что?", true, "18:40"),
        FakeMsg("CS2, вчера обновление вышло норм", false, "18:41"),
        FakeMsg("Окей, после 21 освобожусь", true, "18:42"),
        FakeMsg("Посмотри видос который я скинул", false, "20:44"),
    )),

    ChatTemplate("Макс", "Пн", unread = 0, listOf(
        FakeMsg("Слушай, можешь до зарплаты занять немного?", false, "14:00"),
        FakeMsg("Сколько нужно?", true, "14:15"),
        FakeMsg("Тысяч пять если есть возможность", false, "14:16"),
        FakeMsg("Ок, скину на карту сегодня", true, "14:17"),
        FakeMsg("Спасибо братан, выручил 🤝", false, "14:18"),
        FakeMsg("Не вопрос, отдашь когда будет", true, "14:19"),
    )),

    ChatTemplate("Катя", "Вчера", unread = 0, listOf(
        FakeMsg("Можешь помочь с переездом в субботу?", false, "11:00"),
        FakeMsg("Могу, в котором часу?", true, "11:05"),
        FakeMsg("Часов в 11, если не против", false, "11:06"),
        FakeMsg("Хорошо, буду у тебя", true, "11:07"),
        FakeMsg("Спасибо огромное! 👍", false, "18:30"),
        FakeMsg("Всегда пожалуйста 😊", true, "18:31"),
    )),

    ChatTemplate("Лена", "Пн", unread = 0, listOf(
        FakeMsg("Привет! Не забыл про встречу сегодня?", false, "10:00"),
        FakeMsg("Нет, помню. Уже выхожу", true, "10:28"),
        FakeMsg("Я в том кафе на Ленина, где в прошлый раз", false, "10:29"),
        FakeMsg("Буду через 15 минут, жди", true, "10:30"),
        FakeMsg("Ок, заказала кофе 😊", false, "10:31"),
    )),

    ChatTemplate("Аня", "Вчера", unread = 0, listOf(
        FakeMsg("Ты конспект по матану делал на прошлой неделе?", false, "16:00"),
        FakeMsg("Нет, а что случилось?", true, "16:20"),
        FakeMsg("Завтра контрольная, ты не знал что ли", false, "16:21"),
        FakeMsg("Блин, совсем из головы вылетело", true, "16:22"),
        FakeMsg("Скину тебе свой, только сам разберись нормально", false, "16:23"),
        FakeMsg("Спасибо, ты меня спасла!", true, "16:24"),
    )),

    ChatTemplate("Работа", "13:47", unread = 0, listOf(
        FakeMsg("Всем привет, завтра планёрка в 10:00", false, "09:15"),
        FakeMsg("Понял, буду", true, "09:20"),
        FakeMsg("Я на удалёнке в тот день, подключусь по zoom", false, "09:22"),
        FakeMsg("Ссылку скину утром", false, "09:23"),
        FakeMsg("Встречу перенесли на 16:30 сегодня, не забудьте", false, "13:47"),
    )),

    ChatTemplate("Рабочий чат", "Вчера", unread = 0, listOf(
        FakeMsg("Отчёт по проекту готов?", false, "15:00"),
        FakeMsg("Дорабатываю последние правки, через час пришлю", true, "15:10"),
        FakeMsg("Хорошо, жду. Клиент уже интересовался", false, "15:11"),
        FakeMsg("Понял, постараюсь быстрее", true, "15:12"),
        FakeMsg("Отправил на почту, проверь", true, "16:05"),
        FakeMsg("Получил, спасибо! Всё норм", false, "16:22"),
    )),

    ChatTemplate("Паша", "Вчера", unread = 0, listOf(
        FakeMsg("Едем на дачу в выходные? Давно не были", false, "19:00"),
        FakeMsg("Можно, а кто ещё едет?", true, "19:20"),
        FakeMsg("Мы с Толяном. Возьми мяса, я овощи куплю", false, "19:21"),
        FakeMsg("Договорились. Выезжаем в 10 утра?", true, "19:22"),
        FakeMsg("Да, только не опаздывай как в прошлый раз 😄", false, "19:23"),
    )),

    ChatTemplate("Маша", "Пн", unread = 0, listOf(
        FakeMsg("Ты помнишь что у Кости день рождения через неделю?", false, "12:00"),
        FakeMsg("Да, помню. Что-то планируем?", true, "12:15"),
        FakeMsg("Скидываемся на подарок, ты как?", false, "12:16"),
        FakeMsg("Давай, скину свою долю сегодня", true, "12:17"),
        FakeMsg("Хорошо, я организую всё остальное 👍", false, "12:18"),
    )),

    ChatTemplate("Костя", "Вчера", unread = 0, listOf(
        FakeMsg("Можешь подвезти до метро утром?", false, "21:30"),
        FakeMsg("В котором часу?", true, "21:35"),
        FakeMsg("Часов в 8:30, если не сложно", false, "21:36"),
        FakeMsg("Ок, буду у подъезда", true, "21:37"),
        FakeMsg("Спасибо, выручил!", false, "09:10"),
    )),

    ChatTemplate("Юля", "Пн", unread = 0, listOf(
        FakeMsg("Пойдём в кино в пятницу?", false, "20:00"),
        FakeMsg("Что смотреть будем?", true, "20:10"),
        FakeMsg("Новый триллер, говорят очень хороший", false, "20:11"),
        FakeMsg("Ладно, давай. В котором часу?", true, "20:12"),
        FakeMsg("Сеанс в 19:30, встречаемся у входа в 19:00?", false, "20:13"),
        FakeMsg("Хорошо, договорились 👍", true, "20:14"),
    )),

    ChatTemplate("Витя", "Пн", unread = 0, listOf(
        FakeMsg("Ты где свой телефон брал?", false, "15:00"),
        FakeMsg("В ситилинке, а что?", true, "15:20"),
        FakeMsg("Там сейчас скидки есть?", false, "15:21"),
        FakeMsg("Не знаю, давно брал. На сайте глянь", true, "15:22"),
        FakeMsg("Там 10% до конца месяца оказывается", false, "15:42"),
        FakeMsg("О, значит самое время брать", true, "15:43"),
    )),

    ChatTemplate("Рома", "Вчера", unread = 0, listOf(
        FakeMsg("В зал сегодня идёшь?", false, "16:00"),
        FakeMsg("Да, в 18:30 планирую", true, "16:05"),
        FakeMsg("Подожди меня у входа тогда", false, "16:06"),
        FakeMsg("Ок, жду", true, "16:07"),
        FakeMsg("Опоздаю минут на 15, начинай без меня", false, "18:18"),
        FakeMsg("Понял, не спеши", true, "18:19"),
    )),

    ChatTemplate("Сестра", "Вчера", unread = 0, listOf(
        FakeMsg("Брат, можешь дать денег до зарплаты?", false, "12:00"),
        FakeMsg("Сколько нужно?", true, "12:30"),
        FakeMsg("Тысячи три если есть", false, "12:31"),
        FakeMsg("Есть, скину", true, "12:32"),
        FakeMsg("Спасибо! Ты лучший ❤️", false, "12:33"),
        FakeMsg("Не вопрос 😊", true, "12:34"),
    )),

    ChatTemplate("Оля", "Пн", unread = 0, listOf(
        FakeMsg("Как нормально борщ сварить? Всё время не то выходит", false, "11:00"),
        FakeMsg("Свёклу заранее запеки в духовке, не вари", true, "11:15"),
        FakeMsg("О, правда? Не знала про это", false, "11:16"),
        FakeMsg("Да, минут 40 при 180 градусах. Потом натри и добавь", true, "11:17"),
        FakeMsg("Попробую сегодня, спасибо!", false, "11:18"),
    )),

    ChatTemplate("Группа 312", "Вчера", unread = 0, listOf(
        FakeMsg("Завтра пар нет, Ирина Николаевна заболела", false, "18:00"),
        FakeMsg("Серьёзно? Кайф 🎉", true, "18:05"),
        FakeMsg("Тогда сдача реферата тоже переносится?", false, "18:06"),
        FakeMsg("Да, сказали на следующую среду", false, "18:07"),
        FakeMsg("Огонь, как раз доделаю", true, "18:08"),
    )),

    ChatTemplate("Игорь", "Пн", unread = 0, listOf(
        FakeMsg("Едем на рыбалку в субботу?", false, "19:30"),
        FakeMsg("Надо погоду глянуть", true, "19:45"),
        FakeMsg("Говорят +18, солнечно", false, "19:46"),
        FakeMsg("Тогда да, поедем", true, "19:47"),
        FakeMsg("Встречаемся в 5 утра у меня. Червей я куплю", false, "19:48"),
        FakeMsg("Буду, не засплю 😄", true, "19:49"),
    )),

    ChatTemplate("Наташа", "Пн", unread = 0, listOf(
        FakeMsg("С днём рождения тебя! 🎂🎉", false, "09:00"),
        FakeMsg("Спасибо большое Наташ! ❤️", true, "09:10"),
        FakeMsg("Желаю всего самого лучшего, здоровья и счастья!", false, "09:11"),
        FakeMsg("Ты придёшь вечером?", false, "09:12"),
        FakeMsg("Конечно, буду к 7 часам", true, "09:13"),
    )),
)

private val beaconTeamChat = ChatTemplate(
    name = "Команда B-CON",
    lastTime = "14:20",
    unread = 0,
    messages = listOf(
        FakeMsg("Добро пожаловать в B-CON! 👋", false, "14:15"),
        FakeMsg("Здесь вы можете написать нам, если возникнут вопросы или проблемы.", false, "14:15"),
        FakeMsg("Спасибо!", true, "14:20"),
    )
)

@Composable
fun DecoyScreen() {
    val context = LocalContext.current

    DisposableEffect(Unit) {
        var pressCount = 0
        var firstPressMs = 0L
        val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) {
                val now = System.currentTimeMillis()
                if (now - firstPressMs > 3000L) {
                    pressCount = 1
                    firstPressMs = now
                } else {
                    pressCount++
                    if (pressCount >= 5) {
                        pressCount = 0
                        (context as? MainActivity)?.emergencyWipe(withDecoy = true)
                    }
                }
            }
        }
        context.contentResolver.registerContentObserver(
            Settings.System.CONTENT_URI, true, observer
        )
        onDispose { context.contentResolver.unregisterContentObserver(observer) }
    }

    val selectedChats = remember {
        listOf(beaconTeamChat) +
            UserStorage.getOrCreateDecoySelection(context, chatPool.size, 6)
                .map { chatPool[it] }
    }

    var openedChat by remember { mutableStateOf<ChatTemplate?>(null) }

    BackHandler(enabled = openedChat != null) { openedChat = null }

    if (openedChat != null) {
        DecoyChatScreen(chat = openedChat!!, onBack = { openedChat = null })
    } else {
        DecoyListScreen(chats = selectedChats, onOpenChat = { openedChat = it })
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DecoyListScreen(
    chats: List<ChatTemplate>,
    onOpenChat: (ChatTemplate) -> Unit
) {
    val context = LocalContext.current
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))

    val myDisplayName = remember { UserStorage.getUserDisplayName(context) }
    val myAvatarColor = remember(myDisplayName) {
        decoyAvatarPalette[myDisplayName.hashCode().absoluteValue % decoyAvatarPalette.size]
    }

    Scaffold(
        containerColor = Color.Transparent,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "B-CON",
                        color = Color.White,
                        fontFamily = JetBrainsMono,
                        fontWeight = FontWeight.Bold,
                        fontSize = 22.sp
                    )
                },
                actions = {
                    Box(
                        modifier = Modifier
                            .padding(end = 6.dp)
                            .size(34.dp)
                            .clip(CircleShape)
                            .background(myAvatarColor),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = myDisplayName.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            fontFamily = JetBrainsMono
                        )
                    }
                    IconButton(onClick = {}) {
                        Icon(Icons.Default.Add, contentDescription = null, tint = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
            )
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(bgGradient)
                .padding(padding)
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(top = 8.dp, bottom = 80.dp)
            ) {
                items(chats) { chat ->
                    val avatarColor = avatarColorFor(chat.name)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpenChat(chat) }
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(52.dp)
                                .clip(CircleShape)
                                .background(avatarColor),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = chat.name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                fontSize = 20.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color.White,
                                fontFamily = JetBrainsMono
                            )
                        }
                        Spacer(modifier = Modifier.width(14.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = chat.name,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color.White,
                                fontFamily = JetBrainsMono,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = chat.messages.lastOrNull()?.text ?: "",
                                fontSize = 14.sp,
                                color = c.textPrimary.copy(alpha = 0.55f),
                                fontFamily = JetBrainsMono,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                    HorizontalDivider(
                        modifier = Modifier.padding(start = 82.dp),
                        color = c.textPrimary.copy(alpha = 0.07f),
                        thickness = 0.5.dp
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DecoyChatScreen(
    chat: ChatTemplate,
    onBack: () -> Unit
) {
    val c = LocalBeaconColors.current
    val bgGradient = Brush.verticalGradient(listOf(c.gradientStart, c.gradientEnd))
    val avatarColor = avatarColorFor(chat.name)

    var inputText by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    val allMessages = remember { mutableStateListOf(*chat.messages.toTypedArray()) }

    LaunchedEffect(Unit) {
        if (allMessages.isNotEmpty()) listState.scrollToItem(allMessages.lastIndex)
    }

    Column(modifier = Modifier.fillMaxSize().imePadding()) {

        TopAppBar(
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                }
            },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(shape = CircleShape, color = avatarColor, modifier = Modifier.size(40.dp)) {
                        Box(contentAlignment = Alignment.Center) {
                            Text(
                                text = chat.name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                        }
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            chat.name,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 18.sp,
                            color = Color.White
                        )
                        Text(
                            "в сети",
                            fontSize = 16.sp,
                            color = c.accent
                        )
                    }
                }
            },
            actions = {
                IconButton(onClick = {}) {
                    Icon(Icons.Default.MoreVert, contentDescription = null, tint = Color.White)
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = c.topBar)
        )

        LazyColumn(
            state = listState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(bgGradient)
                .padding(horizontal = 8.dp),
        ) {
            items(allMessages) { msg ->

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 0.dp, vertical = 4.dp)
                ) {
                    Surface(
                        modifier = Modifier
                            .align(if (msg.fromMe) Alignment.CenterEnd else Alignment.CenterStart)
                            .widthIn(max = 280.dp),
                        shape = RoundedCornerShape(
                            topStart = if (msg.fromMe) 18.dp else 4.dp,
                            topEnd   = if (msg.fromMe) 4.dp  else 18.dp,
                            bottomStart = 18.dp,
                            bottomEnd   = 18.dp
                        ),
                        color = if (msg.fromMe) c.bubbleOwn else c.bubbleOther
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.Bottom
                        ) {
                            Text(
                                msg.text,
                                color = Color.White,
                                fontFamily = JetBrainsMono,
                                fontSize = 15.sp,
                                lineHeight = 18.sp,
                                modifier = Modifier.weight(1f, fill = false)
                            )
                            if (msg.fromMe) {
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("✓✓", fontSize = 10.sp, color = Color(0xFF8899AA))
                            }
                        }
                    }
                }
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(c.topBar)
                .padding(8.dp)
                .navigationBarsPadding(),
            verticalAlignment = Alignment.Bottom
        ) {
            IconButton(onClick = {}) {
                Icon(
                    painterResource(R.drawable.ic_attach),
                    contentDescription = null,
                    tint = c.textPrimary,
                    modifier = Modifier.size(26.dp)
                )
            }
            IconButton(onClick = {}) {
                Icon(
                    painterResource(R.drawable.ic_camera_circle),
                    contentDescription = null,
                    tint = c.textPrimary,
                    modifier = Modifier.size(26.dp)
                )
            }
            Box(modifier = Modifier.weight(1f).padding(horizontal = 4.dp)) {
                Canvas(modifier = Modifier.matchParentSize()) {
                    drawRoundRect(
                        color = Color(0x22FFFFFF),
                        cornerRadius = CornerRadius(32.dp.toPx())
                    )
                    drawRoundRect(
                        color = Color(0x33B0C4DE),
                        cornerRadius = CornerRadius(32.dp.toPx()),
                        style = Stroke(width = 1.5.dp.toPx())
                    )
                }
                BasicTextField(
                    value = inputText,
                    onValueChange = { inputText = it },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    maxLines = 3,
                    textStyle = TextStyle(fontSize = 15.sp, color = Color.White),
                    cursorBrush = SolidColor(Color(0xFFFFD700)),
                    decorationBox = { innerTextField ->
                        if (inputText.isEmpty()) {
                            Text(
                                "Сообщение...",
                                fontSize = 15.sp,
                                color = Color(0x88FFFFFF),
                                fontFamily = JetBrainsMono
                            )
                        }
                        innerTextField()
                    }
                )
            }
            IconButton(
                onClick = {
                    val text = inputText.trim()
                    if (text.isNotEmpty()) {
                        val now = java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
                            .format(java.util.Date())
                        allMessages.add(FakeMsg(text, true, now))
                        inputText = ""
                    }
                },
                modifier = Modifier.size(52.dp),
                enabled = inputText.isNotEmpty()
            ) {
                Icon(
                    Icons.Default.Send,
                    contentDescription = null,
                    tint = if (inputText.isNotEmpty()) c.accent else c.textPrimary.copy(alpha = 0.3f)
                )
            }
        }
    }
}
