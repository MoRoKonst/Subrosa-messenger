package com.subrosa.desktop

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
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.absoluteValue

// Desktop port of Android's DecoyScreen.kt — same fake-messenger UI, shown
// after the panic password wipes real data (EmergencyWipe.wipeForDecoyKeepAlive).
// Deliberately omits Android's volume-button-mash emergency-wipe trigger
// (ContentObserver on Settings.System) — no equivalent hardware input on
// desktop, and this screen's only job here is to display convincingly after
// a wipe already happened, not to trigger one itself a second way.

private data class FakeMsg(val text: String, val fromMe: Boolean, val time: String)

private data class ChatTemplate(
    val name: String,
    val messages: List<FakeMsg>
)

private fun decoyAvatarColor(name: String) =
    AVATAR_COLORS[name.hashCode().absoluteValue % AVATAR_COLORS.size]

private val chatPool = listOf(
    ChatTemplate("Sarah", listOf(
        FakeMsg("Hey, how are you? Haven't heard from you in a while", false, "12:40"),
        FakeMsg("Good, just busy with work", true, "13:05"),
        FakeMsg("Are you coming over tonight?", false, "13:06"),
        FakeMsg("I'll try to make it by evening", true, "13:07"),
        FakeMsg("Ok, pick up some bread on the way if you can", false, "14:32"),
    )),
    ChatTemplate("Mike", listOf(
        FakeMsg("How are you feeling? Your voice sounded weird yesterday", false, "09:00"),
        FakeMsg("I'm fine, just tired", true, "09:45"),
        FakeMsg("Are you taking your vitamins?", false, "09:46"),
        FakeMsg("Yes, don't worry about me", true, "09:47"),
        FakeMsg("Good. Made dinner, come over when you can", false, "11:20"),
    )),
    ChatTemplate("John", listOf(
        FakeMsg("When did you last change the oil?", false, "17:00"),
        FakeMsg("October I think, it's been a while", true, "17:20"),
        FakeMsg("Time to do it, you've done 10k miles", false, "17:21"),
        FakeMsg("Yeah, I'll do it this weekend", true, "17:22"),
        FakeMsg("Keys are in the garage, come by and I'll help", false, "17:23"),
    )),
    ChatTemplate("Alex", listOf(
        FakeMsg("Yo, what are you up to tonight?", false, "12:50"),
        FakeMsg("Nothing yet, why?", true, "13:10"),
        FakeMsg("Wanna hang? Haven't seen you in ages", false, "13:11"),
        FakeMsg("Sure, where?", true, "13:12"),
        FakeMsg("Let's go to Chris's place, he's throwing something", false, "13:13"),
        FakeMsg("Ok, what time?", true, "13:14"),
        FakeMsg("How about 7 tomorrow?", false, "14:05"),
    )),
    ChatTemplate("David", listOf(
        FakeMsg("Did you watch the game?", false, "20:00"),
        FakeMsg("Nah, missed it. How was it?", true, "20:30"),
        FakeMsg("3:1, incredible! We dominated them", false, "20:31"),
        FakeMsg("Really? Wish I'd seen it", true, "20:32"),
        FakeMsg("There's another match on Saturday, wanna go?", false, "20:33"),
        FakeMsg("Yeah, remind me", true, "20:34"),
    )),
    ChatTemplate("Chris", listOf(
        FakeMsg("Come over later, let's play something", false, "18:00"),
        FakeMsg("What do you wanna play?", true, "18:40"),
        FakeMsg("CS2, just got an update", false, "18:41"),
        FakeMsg("Cool, I'm free after 9", true, "18:42"),
        FakeMsg("Check out that video I sent you", false, "20:44"),
    )),
    ChatTemplate("James", listOf(
        FakeMsg("Hey, can you lend me some cash till payday?", false, "14:00"),
        FakeMsg("How much do you need?", true, "14:15"),
        FakeMsg("Five hundred if you can", false, "14:16"),
        FakeMsg("Ok, I'll transfer it today", true, "14:17"),
        FakeMsg("Thanks man, lifesaver", false, "14:18"),
        FakeMsg("No problem, pay me back when you can", true, "14:19"),
    )),
    ChatTemplate("Emily", listOf(
        FakeMsg("Can you help me move this Saturday?", false, "11:00"),
        FakeMsg("Sure, what time?", true, "11:05"),
        FakeMsg("Around 11 if that works", false, "11:06"),
        FakeMsg("Perfect, I'll be there", true, "11:07"),
        FakeMsg("Thanks so much!", false, "18:30"),
        FakeMsg("Anytime", true, "18:31"),
    )),
    ChatTemplate("Lisa", listOf(
        FakeMsg("Hey, didn't forget about our meeting?", false, "10:00"),
        FakeMsg("Nope, heading out now", true, "10:28"),
        FakeMsg("I'm at that coffee place downtown like last time", false, "10:29"),
        FakeMsg("Be there in 15, hang tight", true, "10:30"),
        FakeMsg("Ok, already ordered your coffee", false, "10:31"),
    )),
    ChatTemplate("Tom", listOf(
        FakeMsg("Did you do the homework for class?", false, "16:00"),
        FakeMsg("No, what's going on?", true, "16:20"),
        FakeMsg("Quiz tomorrow, didn't you know?", false, "16:21"),
        FakeMsg("Crap, totally forgot", true, "16:22"),
        FakeMsg("I'll send you my notes, study them properly", false, "16:23"),
        FakeMsg("You're a lifesaver!", true, "16:24"),
    )),
    ChatTemplate("Work", listOf(
        FakeMsg("Hey team, standup tomorrow at 10am", false, "09:15"),
        FakeMsg("Got it, see you then", true, "09:20"),
        FakeMsg("I'll be working from home, joining on Zoom", false, "09:22"),
        FakeMsg("I'll send the link in the morning", false, "09:23"),
        FakeMsg("Moved meeting to 4:30 today, don't forget", false, "13:47"),
    )),
    ChatTemplate("Team Chat", listOf(
        FakeMsg("Is the project report done?", false, "15:00"),
        FakeMsg("Finishing up the last changes, sending in an hour", true, "15:10"),
        FakeMsg("Good, client is asking about it", false, "15:11"),
        FakeMsg("I'll get it done ASAP", true, "15:12"),
        FakeMsg("Just sent it to your email", true, "16:05"),
        FakeMsg("Got it, looks great!", false, "16:22"),
    )),
    ChatTemplate("Robert", listOf(
        FakeMsg("Cabin trip this weekend?", false, "19:00"),
        FakeMsg("Sure, who else is coming?", true, "19:20"),
        FakeMsg("Me and Tony. Can you grab some meat?", false, "19:21"),
        FakeMsg("Done. Leave at 10 in the morning?", true, "19:22"),
        FakeMsg("Yeah, but don't be late like last time", false, "19:23"),
    )),
    ChatTemplate("Rachel", listOf(
        FakeMsg("Remember Mark's birthday is next week?", false, "12:00"),
        FakeMsg("Yeah, I remember. We doing something?", true, "12:15"),
        FakeMsg("Let's all chip in for a gift, you in?", false, "12:16"),
        FakeMsg("Sure, I'll send you money today", true, "12:17"),
        FakeMsg("Great, I'll take care of the rest", false, "12:18"),
    )),
    ChatTemplate("Kevin", listOf(
        FakeMsg("Can you pick me up from the station?", false, "21:30"),
        FakeMsg("What time?", true, "21:35"),
        FakeMsg("Around 8:30 if that's ok", false, "21:36"),
        FakeMsg("No problem, I'll be there", true, "21:37"),
        FakeMsg("Thanks, you're the best!", false, "09:10"),
    )),
    ChatTemplate("Jessica", listOf(
        FakeMsg("Wanna catch a movie Friday?", false, "20:00"),
        FakeMsg("Sure, what's playing?", true, "20:10"),
        FakeMsg("New thriller, supposed to be amazing", false, "20:11"),
        FakeMsg("Cool, I'm in. What time?", true, "20:12"),
        FakeMsg("7:30 showing, meet at the entrance at 7?", false, "20:13"),
        FakeMsg("Sounds good", true, "20:14"),
    )),
    ChatTemplate("Brandon", listOf(
        FakeMsg("Where'd you get your phone?", false, "15:00"),
        FakeMsg("Best Buy, why?", true, "15:20"),
        FakeMsg("Any sales going on there?", false, "15:21"),
        FakeMsg("Not sure, check their website", true, "15:22"),
        FakeMsg("Oh they've got 10% off till end of month", false, "15:42"),
        FakeMsg("Nice, guess it's time to upgrade", true, "15:43"),
    )),
    ChatTemplate("Daniel", listOf(
        FakeMsg("Going to the gym today?", false, "16:00"),
        FakeMsg("Yeah, heading there at 6:30", true, "16:05"),
        FakeMsg("Wait for me at the entrance?", false, "16:06"),
        FakeMsg("Ok, I'll wait", true, "16:07"),
        FakeMsg("Running 15 mins late, start without me", false, "18:18"),
        FakeMsg("No problem, take your time", true, "18:19"),
    )),
    ChatTemplate("Lauren", listOf(
        FakeMsg("Can you lend me some cash?", false, "12:00"),
        FakeMsg("How much?", true, "12:30"),
        FakeMsg("Three hundred if you got it", false, "12:31"),
        FakeMsg("Yeah, I'll send it", true, "12:32"),
        FakeMsg("Thanks! You're awesome", false, "12:33"),
        FakeMsg("Anytime", true, "12:34"),
    )),
    ChatTemplate("Sophie", listOf(
        FakeMsg("How do I make a good pasta sauce?", false, "11:00"),
        FakeMsg("Roast the tomatoes first, don't boil them", true, "11:15"),
        FakeMsg("Oh really? I didn't know that", false, "11:16"),
        FakeMsg("Yeah, 40 mins at 350. Makes a huge difference", true, "11:17"),
        FakeMsg("I'll try that today, thanks!", false, "11:18"),
    )),
)

@Composable
fun DecoyScreen() {
    val selectedChats = remember {
        UserStorage.getOrCreateDecoySelection(chatPool.size, 6).map { chatPool[it] }
    }
    var openedChat by remember { mutableStateOf<ChatTemplate?>(null) }

    if (openedChat != null) {
        DecoyChatScreen(chat = openedChat!!, onBack = { openedChat = null })
    } else {
        DecoyListScreen(chats = selectedChats, onOpenChat = { openedChat = it })
    }
}

@Composable
private fun DecoyListScreen(
    chats: List<ChatTemplate>,
    onOpenChat: (ChatTemplate) -> Unit
) {
    val myDisplayName = remember { UserStorage.getUsername().ifBlank { "Me" } }
    val myAvatarColor = remember(myDisplayName) { decoyAvatarColor(myDisplayName) }
    val bgGradient = Brush.verticalGradient(listOf(SubrosaTheme.gradientStart, SubrosaTheme.gradientEnd))

    Column(Modifier.fillMaxSize()) {
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Subrosa",
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                    color = SubrosaTheme.accent,
                    modifier = Modifier.weight(1f)
                )
                Box(
                    modifier = Modifier.size(34.dp).background(myAvatarColor, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = myDisplayName.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }
            }
        }
        Box(Modifier.fillMaxSize().background(bgGradient)) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(top = 8.dp, bottom = 24.dp)
            ) {
                items(chats) { chat ->
                    val avatarColor = decoyAvatarColor(chat.name)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpenChat(chat) }
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier.size(52.dp).background(avatarColor, CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = chat.name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                                fontSize = 22.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Color.White
                            )
                        }
                        Spacer(Modifier.width(14.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                text = chat.name,
                                fontSize = 18.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = SubrosaTheme.textPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Spacer(Modifier.height(2.dp))
                            Text(
                                text = chat.messages.lastOrNull()?.text ?: "",
                                fontSize = 16.sp,
                                color = SubrosaTheme.textSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Text(
                            text = chat.messages.lastOrNull()?.time ?: "",
                            fontSize = 13.sp,
                            color = SubrosaTheme.textSecondary
                        )
                    }
                    HorizontalDivider(
                        modifier = Modifier.padding(start = 82.dp),
                        color = SubrosaTheme.divider,
                        thickness = 0.5.dp
                    )
                }
            }
        }
    }
}

@Composable
private fun DecoyChatScreen(chat: ChatTemplate, onBack: () -> Unit) {
    val bgGradient = Brush.verticalGradient(listOf(SubrosaTheme.gradientStart, SubrosaTheme.gradientEnd))
    val avatarColor = decoyAvatarColor(chat.name)

    var inputText by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    val allMessages = remember { mutableStateListOf(*chat.messages.toTypedArray()) }

    LaunchedEffect(Unit) {
        if (allMessages.isNotEmpty()) listState.scrollToItem(allMessages.lastIndex)
    }

    Column(Modifier.fillMaxSize()) {
        Surface(color = SubrosaTheme.topBar, shadowElevation = 2.dp) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(AppIcons.get("BACK_ARROW"), contentDescription = null, tint = SubrosaTheme.textPrimary)
                }
                Box(
                    modifier = Modifier.size(40.dp).background(avatarColor, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = chat.name.firstOrNull()?.uppercaseChar()?.toString() ?: "?",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(chat.name, fontWeight = FontWeight.SemiBold, fontSize = 19.sp, color = SubrosaTheme.textPrimary)
                    Text("online", fontSize = 14.sp, color = SubrosaTheme.accent)
                }
            }
        }

        LazyColumn(
            state = listState,
            modifier = Modifier.weight(1f).fillMaxWidth().background(bgGradient).padding(horizontal = 8.dp)
        ) {
            items(allMessages) { msg ->
                Box(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
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
                        color = if (msg.fromMe) SubrosaTheme.bubbleOwn else SubrosaTheme.bubbleOther
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.Bottom
                        ) {
                            Text(
                                msg.text,
                                color = SubrosaTheme.textPrimary,
                                fontSize = 17.sp,
                                lineHeight = 18.sp,
                                modifier = Modifier.weight(1f, fill = false)
                            )
                            if (msg.fromMe) {
                                Spacer(Modifier.width(4.dp))
                                Icon(AppIcons.get("DELIVERED_DOUBLE"), contentDescription = null,
                                    tint = SubrosaTheme.sentTick, modifier = Modifier.size(12.dp))
                            }
                        }
                    }
                }
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth().background(SubrosaTheme.topBar).padding(8.dp),
            verticalAlignment = Alignment.Bottom
        ) {
            IconButton(onClick = {}) {
                Icon(AppIcons.get("ATTACH"), contentDescription = null, tint = SubrosaTheme.textPrimary, modifier = Modifier.size(20.dp))
            }
            Box(modifier = Modifier.weight(1f).padding(horizontal = 4.dp)) {
                Canvas(modifier = Modifier.matchParentSize()) {
                    drawRoundRect(color = Color(0x22FFFFFF), cornerRadius = CornerRadius(32.dp.toPx()))
                    drawRoundRect(
                        color = Color(0x33B0C4DE),
                        cornerRadius = CornerRadius(32.dp.toPx()),
                        style = Stroke(width = 1.5.dp.toPx())
                    )
                }
                BasicTextField(
                    value = inputText,
                    onValueChange = { inputText = it },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                    maxLines = 3,
                    textStyle = TextStyle(fontSize = 17.sp, color = SubrosaTheme.textPrimary),
                    cursorBrush = SolidColor(SubrosaTheme.accent),
                    decorationBox = { innerTextField ->
                        if (inputText.isEmpty()) {
                            Text("Message...", fontSize = 17.sp, color = SubrosaTheme.textSecondary)
                        }
                        innerTextField()
                    }
                )
            }
            IconButton(
                onClick = {
                    val text = inputText.trim()
                    if (text.isNotEmpty()) {
                        val now = java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault()).format(java.util.Date())
                        allMessages.add(FakeMsg(text, true, now))
                        inputText = ""
                    }
                },
                enabled = inputText.isNotEmpty()
            ) {
                Icon(
                    AppIcons.get("Send"),
                    contentDescription = null,
                    tint = if (inputText.isNotEmpty()) SubrosaTheme.accent else SubrosaTheme.textSecondary.copy(alpha = 0.4f)
                )
            }
        }
    }
}
