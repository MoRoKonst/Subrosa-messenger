package com.subrosa.desktop

import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64

data class Channel(
    val id: String,
    val name: String,
    val description: String = "",
    val avatar: String = "📢",
    val adminId: String,
    val adminName: String = "",
    val isAdmin: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val isMuted: Boolean = false,
    val subscriberCount: Int = -1,
    val pinnedPostId: String? = null
)

data class ChannelPost(
    val id: String,
    val channelId: String,
    val text: String,
    val timestamp: Long,
    val authorId: String,
    val authorName: String,
    val imageData: String = ""
)

object ChannelManager {

    private const val KEY_LIST = "channels_list"

    val channelUpdateEvents = MutableStateFlow(0L)

    fun getChannels(): List<Channel> {
        val json = DesktopStorage.get(KEY_LIST) ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Channel(
                    id              = o.getString("id"),
                    name            = o.getString("name"),
                    description     = o.optString("description", ""),
                    avatar          = o.optString("avatar", "📢"),
                    adminId         = o.optString("adminId", ""),
                    adminName       = o.optString("adminName", ""),
                    isAdmin         = o.optBoolean("isAdmin", false),
                    createdAt       = o.optLong("createdAt", 0L),
                    isMuted         = o.optBoolean("isMuted", false),
                    subscriberCount = o.optInt("subscriberCount", -1),
                    pinnedPostId    = o.optString("pinnedPostId", "").takeIf { it.isNotEmpty() }
                )
            }
        } catch (e: Exception) { emptyList() }
    }

    fun saveChannel(channel: Channel) {
        val list = getChannels().toMutableList()
        list.removeIf { it.id == channel.id }
        list.add(channel)
        DesktopStorage.put(KEY_LIST, serializeChannels(list))
        channelUpdateEvents.value = System.currentTimeMillis()
    }

    fun removeChannel(channelId: String) {
        val list = getChannels().filter { it.id != channelId }
        DesktopStorage.put(KEY_LIST, serializeChannels(list))
        DesktopStorage.remove("ch_posts_$channelId")
        channelUpdateEvents.value = System.currentTimeMillis()
    }

    fun getChannel(channelId: String): Channel? = getChannels().find { it.id == channelId }

    private fun serializeChannels(list: List<Channel>): String {
        val arr = JSONArray()
        list.forEach { c ->
            arr.put(JSONObject().apply {
                put("id", c.id)
                put("name", c.name)
                put("description", c.description)
                put("avatar", c.avatar)
                put("adminId", c.adminId)
                put("adminName", c.adminName)
                put("isAdmin", c.isAdmin)
                put("createdAt", c.createdAt)
                put("isMuted", c.isMuted)
                put("subscriberCount", c.subscriberCount)
                if (c.pinnedPostId != null) put("pinnedPostId", c.pinnedPostId)
            })
        }
        return arr.toString()
    }

    fun addPost(post: ChannelPost) {
        val posts = loadPosts(post.channelId).toMutableList()
        posts.removeIf { it.id == post.id }
        posts.add(post)
        val trimmed = if (posts.size > 200) posts.takeLast(200) else posts
        savePosts(post.channelId, trimmed)
    }

    fun removePost(channelId: String, postId: String) {
        val posts = loadPosts(channelId).filter { it.id != postId }
        savePosts(channelId, posts)
        channelUpdateEvents.value = System.currentTimeMillis()
    }

    fun loadPosts(channelId: String): List<ChannelPost> {
        val json = DesktopStorage.get("ch_posts_$channelId") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                ChannelPost(
                    id         = o.getString("id"),
                    channelId  = o.getString("channelId"),
                    text       = o.getString("text"),
                    timestamp  = o.getLong("timestamp"),
                    authorId   = o.optString("authorId", ""),
                    authorName = o.optString("authorName", ""),
                    imageData  = o.optString("imageData", "")
                )
            }.sortedBy { it.timestamp }
        } catch (e: Exception) { emptyList() }
    }

    private fun savePosts(channelId: String, posts: List<ChannelPost>) {
        val arr = JSONArray()
        posts.forEach { p ->
            arr.put(JSONObject().apply {
                put("id", p.id)
                put("channelId", p.channelId)
                put("text", p.text)
                put("timestamp", p.timestamp)
                put("authorId", p.authorId)
                put("authorName", p.authorName)
                put("imageData", p.imageData)
            })
        }
        DesktopStorage.put("ch_posts_$channelId", arr.toString())
    }

    fun generateSubscribeLink(channelId: String, channelName: String, channelAvatar: String = "📢"): String {
        val nb = Base64.getUrlEncoder().withoutPadding().encodeToString(channelName.toByteArray(Charsets.UTF_8))
        val ab = Base64.getUrlEncoder().withoutPadding().encodeToString(channelAvatar.toByteArray(Charsets.UTF_8))
        return "beacon://channel?id=$channelId&name=$nb&avatar=$ab"
    }

    data class ChannelLinkData(val channelId: String, val channelName: String, val channelAvatar: String)

    fun parseChannelLink(link: String): ChannelLinkData? {
        return try {
            val trimmed = link.trim()
            if (!trimmed.startsWith("beacon://channel")) return null
            val uri = URI(trimmed)
            val query = (uri.rawSchemeSpecificPart.substringAfter("?", ""))
                .split("&")
                .mapNotNull {
                    val idx = it.indexOf('=')
                    if (idx < 0) null else it.substring(0, idx) to it.substring(idx + 1)
                }.toMap()
            val id = query["id"] ?: return null
            val nameB64 = query["name"] ?: return null
            val avatarB64 = query["avatar"]
            val name = String(Base64.getUrlDecoder().decode(nameB64), Charsets.UTF_8)
            val avatar = if (!avatarB64.isNullOrBlank())
                String(Base64.getUrlDecoder().decode(avatarB64), Charsets.UTF_8)
            else "📢"
            ChannelLinkData(id, name, avatar)
        } catch (e: Exception) { null }
    }
}
