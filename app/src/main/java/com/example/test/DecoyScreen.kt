package com.subrosa.messenger

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
import com.subrosa.messenger.ui.theme.LocalsubrosaColors
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

    ChatTemplate("Sarah", "14:32", unread = 0, listOf(
        FakeMsg("Hey, how are you? Haven't heard from you in a while", false, "12:40"),
        FakeMsg("Good, just busy with work", true, "13:05"),
        FakeMsg("Are you coming over tonight?", false, "13:06"),
        FakeMsg("I'll try to make it by evening", true, "13:07"),
        FakeMsg("Ok, pick up some bread on the way if you can", false, "14:32"),
    )),

    ChatTemplate("Mike", "11:20", unread = 1, listOf(
        FakeMsg("How are you feeling? Your voice sounded weird yesterday", false, "09:00"),
        FakeMsg("I'm fine, just tired", true, "09:45"),
        FakeMsg("Are you taking your vitamins?", false, "09:46"),
        FakeMsg("Yes, don't worry about me", true, "09:47"),
        FakeMsg("Good. Made dinner, come over when you can", false, "11:20"),
    )),

    ChatTemplate("John", "Yesterday", unread = 0, listOf(
        FakeMsg("When did you last change the oil?", false, "17:00"),
        FakeMsg("October I think, it's been a while", true, "17:20"),
        FakeMsg("Time to do it, you've done 10k miles", false, "17:21"),
        FakeMsg("Yeah, I'll do it this weekend", true, "17:22"),
        FakeMsg("Keys are in the garage, come by and I'll help", false, "17:23"),
    )),

    ChatTemplate("Alex", "14:05", unread = 2, listOf(
        FakeMsg("Yo, what are you up to tonight?", false, "12:50"),
        FakeMsg("Nothing yet, why?", true, "13:10"),
        FakeMsg("Wanna hang? Haven't seen you in ages", false, "13:11"),
        FakeMsg("Sure, where?", true, "13:12"),
        FakeMsg("Let's go to Chris's place, he's throwing something", false, "13:13"),
        FakeMsg("Ok, what time?", true, "13:14"),
        FakeMsg("How about 7 tomorrow?", false, "14:05"),
    )),

    ChatTemplate("David", "Yesterday", unread = 0, listOf(
        FakeMsg("Did you watch the game?", false, "20:00"),
        FakeMsg("Nah, missed it. How was it?", true, "20:30"),
        FakeMsg("3:1, incredible! We dominated them", false, "20:31"),
        FakeMsg("Really? Wish I'd seen it", true, "20:32"),
        FakeMsg("There's another match on Saturday, wanna go?", false, "20:33"),
        FakeMsg("Yeah, remind me", true, "20:34"),
    )),

    ChatTemplate("Chris", "Yesterday", unread = 1, listOf(
        FakeMsg("Come over later, let's play something", false, "18:00"),
        FakeMsg("What do you wanna play?", true, "18:40"),
        FakeMsg("CS2, just got an update", false, "18:41"),
        FakeMsg("Cool, I'm free after 9", true, "18:42"),
        FakeMsg("Check out that video I sent you", false, "20:44"),
    )),

    ChatTemplate("James", "Mon", unread = 0, listOf(
        FakeMsg("Hey, can you lend me some cash till payday?", false, "14:00"),
        FakeMsg("How much do you need?", true, "14:15"),
        FakeMsg("Five hundred if you can", false, "14:16"),
        FakeMsg("Ok, I'll transfer it today", true, "14:17"),
        FakeMsg("Thanks man, lifesaver 🤝", false, "14:18"),
        FakeMsg("No problem, pay me back when you can", true, "14:19"),
    )),

    ChatTemplate("Emily", "Yesterday", unread = 0, listOf(
        FakeMsg("Can you help me move this Saturday?", false, "11:00"),
        FakeMsg("Sure, what time?", true, "11:05"),
        FakeMsg("Around 11 if that works", false, "11:06"),
        FakeMsg("Perfect, I'll be there", true, "11:07"),
        FakeMsg("Thanks so much! 👍", false, "18:30"),
        FakeMsg("Anytime 😊", true, "18:31"),
    )),

    ChatTemplate("Lisa", "Mon", unread = 0, listOf(
        FakeMsg("Hey, didn't forget about our meeting?", false, "10:00"),
        FakeMsg("Nope, heading out now", true, "10:28"),
        FakeMsg("I'm at that coffee place downtown like last time", false, "10:29"),
        FakeMsg("Be there in 15, hang tight", true, "10:30"),
        FakeMsg("Ok, already ordered your coffee 😊", false, "10:31"),
    )),

    ChatTemplate("Tom", "Yesterday", unread = 0, listOf(
        FakeMsg("Did you do the homework for class?", false, "16:00"),
        FakeMsg("No, what's going on?", true, "16:20"),
        FakeMsg("Quiz tomorrow, didn't you know?", false, "16:21"),
        FakeMsg("Crap, totally forgot", true, "16:22"),
        FakeMsg("I'll send you my notes, study them properly", false, "16:23"),
        FakeMsg("You're a lifesaver!", true, "16:24"),
    )),

    ChatTemplate("Work", "13:47", unread = 0, listOf(
        FakeMsg("Hey team, standup tomorrow at 10am", false, "09:15"),
        FakeMsg("Got it, see you then", true, "09:20"),
        FakeMsg("I'll be working from home, joining on Zoom", false, "09:22"),
        FakeMsg("I'll send the link in the morning", false, "09:23"),
        FakeMsg("Moved meeting to 4:30 today, don't forget", false, "13:47"),
    )),

    ChatTemplate("Team Chat", "Yesterday", unread = 0, listOf(
        FakeMsg("Is the project report done?", false, "15:00"),
        FakeMsg("Finishing up the last changes, sending in an hour", true, "15:10"),
        FakeMsg("Good, client is asking about it", false, "15:11"),
        FakeMsg("I'll get it done ASAP", true, "15:12"),
        FakeMsg("Just sent it to your email", true, "16:05"),
        FakeMsg("Got it, looks great!", false, "16:22"),
    )),

    ChatTemplate("Robert", "Yesterday", unread = 0, listOf(
        FakeMsg("Cabin trip this weekend?", false, "19:00"),
        FakeMsg("Sure, who else is coming?", true, "19:20"),
        FakeMsg("Me and Tony. Can you grab some meat?", false, "19:21"),
        FakeMsg("Done. Leave at 10 in the morning?", true, "19:22"),
        FakeMsg("Yeah, but don't be late like last time 😄", false, "19:23"),
    )),

    ChatTemplate("Rachel", "Mon", unread = 0, listOf(
        FakeMsg("Remember Mark's birthday is next week?", false, "12:00"),
        FakeMsg("Yeah, I remember. We doing something?", true, "12:15"),
        FakeMsg("Let's all chip in for a gift, you in?", false, "12:16"),
        FakeMsg("Sure, I'll send you money today", true, "12:17"),
        FakeMsg("Great, I'll take care of the rest 👍", false, "12:18"),
    )),

    ChatTemplate("Kevin", "Yesterday", unread = 0, listOf(
        FakeMsg("Can you pick me up from the station?", false, "21:30"),
        FakeMsg("What time?", true, "21:35"),
        FakeMsg("Around 8:30 if that's ok", false, "21:36"),
        FakeMsg("No problem, I'll be there", true, "21:37"),
        FakeMsg("Thanks, you're the best!", false, "09:10"),
    )),

    ChatTemplate("Jessica", "Mon", unread = 0, listOf(
        FakeMsg("Wanna catch a movie Friday?", false, "20:00"),
        FakeMsg("Sure, what's playing?", true, "20:10"),
        FakeMsg("New thriller, supposed to be amazing", false, "20:11"),
        FakeMsg("Cool, I'm in. What time?", true, "20:12"),
        FakeMsg("7:30 showing, meet at the entrance at 7?", false, "20:13"),
        FakeMsg("Sounds good 👍", true, "20:14"),
    )),

    ChatTemplate("Brandon", "Mon", unread = 0, listOf(
        FakeMsg("Where'd you get your phone?", false, "15:00"),
        FakeMsg("Best Buy, why?", true, "15:20"),
        FakeMsg("Any sales going on there?", false, "15:21"),
        FakeMsg("Not sure, check their website", true, "15:22"),
        FakeMsg("Oh they've got 10% off till end of month", false, "15:42"),
        FakeMsg("Nice, guess it's time to upgrade", true, "15:43"),
    )),

    ChatTemplate("Daniel", "Yesterday", unread = 0, listOf(
        FakeMsg("Going to the gym today?", false, "16:00"),
        FakeMsg("Yeah, heading there at 6:30", true, "16:05"),
        FakeMsg("Wait for me at the entrance?", false, "16:06"),
        FakeMsg("Ok, I'll wait", true, "16:07"),
        FakeMsg("Running 15 mins late, start without me", false, "18:18"),
        FakeMsg("No problem, take your time", true, "18:19"),
    )),

    ChatTemplate("Lauren", "Yesterday", unread = 0, listOf(
        FakeMsg("Can you lend me some cash?", false, "12:00"),
        FakeMsg("How much?", true, "12:30"),
        FakeMsg("Three hundred if you got it", false, "12:31"),
        FakeMsg("Yeah, I'll send it", true, "12:32"),
        FakeMsg("Thanks! You're awesome ❤️", false, "12:33"),
        FakeMsg("Anytime 😊", true, "12:34"),
    )),

    ChatTemplate("Sophie", "Mon", unread = 0, listOf(
        FakeMsg("How do I make a good pasta sauce?", false, "11:00"),
        FakeMsg("Roast the tomatoes first, don't boil them", true, "11:15"),
        FakeMsg("Oh really? I didn't know that", false, "11:16"),
        FakeMsg("Yeah, 40 mins at 350. Makes a huge difference", true, "11:17"),
        FakeMsg("I'll try that today, thanks!", false, "11:18"),
    )),

    ChatTemplate("Class Group", "Yesterday", unread = 0, listOf(
        FakeMsg("No class tomorrow, professor is sick", false, "18:00"),
        FakeMsg("Oh nice 🎉", true, "18:05"),
        FakeMsg("Does this mean the essay is postponed too?", false, "18:06"),
        FakeMsg("Yeah, new deadline next week", false, "18:07"),
        FakeMsg("Finally some breathing room", true, "18:08"),
    )),

    ChatTemplate("Matt", "Mon", unread = 0, listOf(
        FakeMsg("Fishing trip Saturday?", false, "19:30"),
        FakeMsg("Let me check the weather first", true, "19:45"),
        FakeMsg("Forecast says 72 and sunny", false, "19:46"),
        FakeMsg("Sounds perfect", true, "19:47"),
        FakeMsg("Meet me at 5am. I'll get the bait", false, "19:48"),
        FakeMsg("Good, I won't be late 😄", true, "19:49"),
    )),

    ChatTemplate("Amy", "Mon", unread = 0, listOf(
        FakeMsg("Happy birthday! 🎂🎉", false, "09:00"),
        FakeMsg("Thanks so much Amy! ❤️", true, "09:10"),
        FakeMsg("Hope you have an amazing day!", false, "09:11"),
        FakeMsg("Will you be at the party tonight?", false, "09:12"),
        FakeMsg("Absolutely, see you at 7!", true, "09:13"),
    )),
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
    val c = LocalsubrosaColors.current
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
    val c = LocalsubrosaColors.current
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
                            "online",
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
                                "Message...",
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
