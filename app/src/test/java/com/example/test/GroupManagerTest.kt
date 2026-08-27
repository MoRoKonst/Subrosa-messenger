package com.subrosa.messenger

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Regression tests for the two highest-priority open items in
 * docs/THREAT_MODEL.md (threats B and C): GroupManager's internal
 * authorization check, and the invariant that a removed group member's id
 * is actually gone from persisted membership -- the state
 * GroupInfoScreen.rotateGroupKey's recipient list is built from.
 */
// sdk pinned to 34: Robolectric 4.16.1's newest supported SDK is 36, and
// this project's compileSdk (37) is used as the implicit target otherwise.
@Config(sdk = [34])
@RunWith(RobolectricTestRunner::class)
class GroupManagerTest {

    private lateinit var context: Context
    private val groupId = "test-group-1"
    private val admin = "ADMIN0001"
    private val memberB = "MEMBERB01"
    private val memberC = "MEMBERC01"

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        // Robolectric has no working AndroidKeyStore simulation, so the real
        // EncryptedSharedPreferences path (which GroupManager uses in
        // production) can't run here -- see the comment on
        // GroupManager.prefsProvider. Plain SharedPreferences is fine: the
        // authorization/membership logic under test doesn't depend on the
        // storage layer being encrypted.
        GroupManager.prefsProvider = { ctx, name -> ctx.getSharedPreferences(name, Context.MODE_PRIVATE) }
        context.getSharedPreferences("groups", Context.MODE_PRIVATE).edit().clear().commit()
        GroupManager.saveGroup(
            context,
            Group(
                id = groupId,
                name = "Test group",
                avatar = "",
                members = listOf(admin, memberB, memberC),
                admins = listOf(admin),
                createdBy = admin
            )
        )
    }

    @Test
    fun `non-admin cannot remove another member`() {
        GroupManager.removeMember(context, groupId, memberB, memberC)

        val group = GroupManager.getGroup(context, groupId)!!
        assertTrue("removal by a non-admin must be rejected", group.members.contains(memberC))
    }

    @Test
    fun `member can remove themselves without being admin`() {
        GroupManager.removeMember(context, groupId, memberB, memberB)

        val group = GroupManager.getGroup(context, groupId)!!
        assertFalse("self-removal must succeed even for a non-admin", group.members.contains(memberB))
    }

    @Test
    fun `admin can remove another member, and the removed id is actually gone from persisted state`() {
        GroupManager.removeMember(context, groupId, admin, memberC)

        val group = GroupManager.getGroup(context, groupId)!!
        // This is the exact invariant GroupInfoScreen's rotateGroupKey call
        // site depends on: it reloads the group from storage after removal
        // and sends the rotated key only to group.members. If a removed
        // member's id could still be present here, they would receive the
        // new key.
        assertFalse("removed member must not appear in persisted membership", group.members.contains(memberC))
        assertTrue(group.members.contains(admin))
        assertTrue(group.members.contains(memberB))
    }

    @Test
    fun `non-admin cannot add a new member`() {
        GroupManager.addMember(context, groupId, memberB, "NEWMEMBER1")

        val group = GroupManager.getGroup(context, groupId)!!
        assertFalse("add by a non-admin must be rejected", group.members.contains("NEWMEMBER1"))
    }

    @Test
    fun `admin can add a new member`() {
        GroupManager.addMember(context, groupId, admin, "NEWMEMBER1")

        val group = GroupManager.getGroup(context, groupId)!!
        assertTrue(group.members.contains("NEWMEMBER1"))
    }

    @Test
    fun `non-admin cannot promote another member to admin`() {
        GroupManager.promoteToAdmin(context, groupId, memberB, memberC)

        val group = GroupManager.getGroup(context, groupId)!!
        assertFalse("promotion by a non-admin must be rejected", group.admins.contains(memberC))
    }

    @Test
    fun `admin can promote another member to admin`() {
        GroupManager.promoteToAdmin(context, groupId, admin, memberB)

        val group = GroupManager.getGroup(context, groupId)!!
        assertTrue(group.admins.contains(memberB))
    }

    @Test
    fun `removed admin loses admin status via isAdmin, even if still listed in admins by a bug`() {
        // isAdmin() requires current membership, not just presence in the
        // admins list (see the comment on isAdmin in GroupManager.kt) --
        // covers the "removed admin still treated as admin forever" bug
        // this check was added to close.
        GroupManager.removeMember(context, groupId, admin, admin)

        assertFalse(GroupManager.isAdmin(context, groupId, admin))
        // With no admin left, no one (not even the former admin) can mutate
        // the group anymore -- this is a real consequence of the fix, not a
        // separate bug: a group's last admin leaving orphans the group.
        GroupManager.addMember(context, groupId, memberB, "NEWMEMBER1")
        val group = GroupManager.getGroup(context, groupId)!!
        assertFalse(group.members.contains("NEWMEMBER1"))
    }

    @Test
    fun `concurrent removals of two different members do not lose an update`() {
        val threads = listOf(memberB, memberC).map { target ->
            Thread { GroupManager.removeMember(context, groupId, admin, target) }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        val group = GroupManager.getGroup(context, groupId)!!
        assertEquals(listOf(admin), group.members)
    }
}
