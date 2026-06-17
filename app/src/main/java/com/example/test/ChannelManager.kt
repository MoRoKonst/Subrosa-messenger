package com.bcon.messenger

import android.content.Context
import android.util.Base64
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONArray
import org.json.JSONObject

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

    private const val PREFS_CHANNELS = "subscribed_channels"
    private const val KEY_LIST = "channels_list"

    /** Bumped on every saveChannel / removePost — ChannelFeedScreen collects this to refresh UI */
    val channelUpdateEvents = MutableStateFlow(0L)

    // ─── Channels ────────────────────────────────────────────────────────────

    fun getChannels(context: Context): List<Channel> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_CHANNELS)
        val json = prefs.getString(KEY_LIST, "[]") ?: "[]"
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Channel(
                    id             = o.getString("id"),
                    name           = o.getString("name"),
                    description    = o.optString("description", ""),
                    avatar         = o.optString("avatar", "📢"),
                    adminId        = o.optString("adminId", ""),
                    adminName      = o.optString("adminName", ""),
                    isAdmin        = o.optBoolean("isAdmin", false),
                    createdAt      = o.optLong("createdAt", 0L),
                    isMuted        = o.optBoolean("isMuted", false),
                    subscriberCount = o.optInt("subscriberCount", -1),
                    pinnedPostId   = o.optString("pinnedPostId", "").takeIf { it.isNotEmpty() }
                )
            }
        } catch (e: Exception) { emptyList() }
    }

    fun saveChannel(context: Context, channel: Channel) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_CHANNELS)
        val list = getChannels(context).toMutableList()
        list.removeIf { it.id == channel.id }
        list.add(channel)
        prefs.edit().putString(KEY_LIST, serializeChannels(list)).apply()
        channelUpdateEvents.value = System.currentTimeMillis()
    }

    fun removeChannel(context: Context, channelId: String) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, PREFS_CHANNELS)
        val list = getChannels(context).filter { it.id != channelId }
        prefs.edit().putString(KEY_LIST, serializeChannels(list)).apply()
        // Clear cached posts
        EncryptedStorage.getEncryptedPrefs(context, "ch_posts_$channelId")
            .edit().clear().apply()
        channelUpdateEvents.value = System.currentTimeMillis()
    }

    fun getChannel(context: Context, channelId: String): Channel? =
        getChannels(context).find { it.id == channelId }

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

    // ─── Posts ───────────────────────────────────────────────────────────────

    fun addPost(context: Context, post: ChannelPost) {
        val posts = loadPosts(context, post.channelId).toMutableList()
        posts.removeIf { it.id == post.id }
        posts.add(post)
        val trimmed = if (posts.size > 200) posts.takeLast(200) else posts
        savePosts(context, post.channelId, trimmed)
    }

    fun removePost(context: Context, channelId: String, postId: String) {
        val posts = loadPosts(context, channelId).filter { it.id != postId }
        savePosts(context, channelId, posts)
        channelUpdateEvents.value = System.currentTimeMillis()
    }

    fun loadPosts(context: Context, channelId: String): List<ChannelPost> {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, "ch_posts_$channelId")
        val json = prefs.getString("posts", "[]") ?: "[]"
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

    private fun savePosts(context: Context, channelId: String, posts: List<ChannelPost>) {
        val prefs = EncryptedStorage.getEncryptedPrefs(context, "ch_posts_$channelId")
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
        prefs.edit().putString("posts", arr.toString()).apply()
    }

    // ─── Links ───────────────────────────────────────────────────────────────

    /**
     * Generates a subscribe deep link for the channel.
     * Format: beacon://channel?id=CHANNEL_ID&name=NAME_B64&avatar=AVATAR_B64
     */
    fun generateSubscribeLink(
        channelId: String,
        channelName: String,
        channelAvatar: String = "📢"
    ): String {
        val nb = Base64.encodeToString(channelName.toByteArray(Charsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP)
        val ab = Base64.encodeToString(channelAvatar.toByteArray(Charsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP)
        return "beacon://channel?id=$channelId&name=$nb&avatar=$ab"
    }

    data class ChannelLinkData(val channelId: String, val channelName: String, val channelAvatar: String)

    fun parseChannelLink(link: String): ChannelLinkData? {
        return try {
            val uri = android.net.Uri.parse(link.trim())
            if (uri.scheme != "beacon" || uri.host != "channel") return null
            val id = uri.getQueryParameter("id") ?: return null
            val nameB64 = uri.getQueryParameter("name") ?: return null
            val avatarB64 = uri.getQueryParameter("avatar")
            val name = String(Base64.decode(nameB64, Base64.URL_SAFE), Charsets.UTF_8)
            val avatar = if (!avatarB64.isNullOrBlank())
                String(Base64.decode(avatarB64, Base64.URL_SAFE), Charsets.UTF_8)
            else "📢"
            ChannelLinkData(id, name, avatar)
        } catch (e: Exception) { null }
    }
}
