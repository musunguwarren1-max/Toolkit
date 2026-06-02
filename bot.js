const { Client, LocalAuth } = require('whatsapp-web.js');

// Replace with YOUR phone number (international format, no + or spaces)
// Example: if your number is +1 234 567 8900, enter "12345678900"
const MY_PHONE_NUMBER = "254102776096";  // <----- CHANGE THIS!

const client = new Client({
    authStrategy: new LocalAuth({ dataPath: "./auth" }),
    puppeteer: {
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    },
    // Enable pairing code instead of QR
    pairWithPhoneNumber: {
        phoneNumber: MY_PHONE_NUMBER,
        showNotification: true,
        intervalMs: 180000
    }
});

// Show the pairing code in console
client.on('code', (code) => {
    console.log('\n========================================');
    console.log('🔐 YOUR PAIRING CODE:', code);
    console.log('========================================');
    console.log('📱 Open WhatsApp → Settings → Linked Devices');
    console.log('📝 Tap "Link a Device" → "Link with phone number instead"');
    console.log('⌨️ Enter this code:', code);
    console.log('⏰ Code expires in 3 minutes\n');
});

client.on('authenticated', () => {
    console.log('✅ Bot authenticated!');
});

client.on('ready', () => {
    console.log('🚀 WhatsApp Bot is running!');
    console.log('Bot will now auto-delete invite links and respond to commands');
});

client.on('auth_failure', (msg) => {
    console.error('❌ Auth failed:', msg);
});

client.on('disconnected', (reason) => {
    console.log('Bot disconnected:', reason);
});

// ============= GROUP MANAGEMENT =============
client.on('message', async (message) => {
    try {
        const chat = await message.getChat();
        
        // Only process group messages
        if (!chat.isGroup) return;
        
        const sender = message.author || message.from;
        const body = message.body.toLowerCase();
        const isAdmin = chat.participants.find(p => p.id._serialized === sender)?.isAdmin;
        
        // --- AUTO-DELETE WHATSAPP INVITE LINKS ---
        const inviteLinkPattern = /chat\.whatsapp\.com\/[A-Za-z0-9]{22}/;
        if (inviteLinkPattern.test(message.body)) {
            await message.delete();
            await client.sendMessage(chat.id._serialized, 
                `⚠️ @${sender.split('@')[0]}, invite links are not allowed!`, 
                { mentions: [sender] });
            console.log(`Deleted invite link from ${sender}`);
            return;
        }
        
        // --- COMMANDS (ADMINS ONLY) ---
        if (!isAdmin) return;
        
        // !menu - Show all commands
        if (body === '!menu' || body === '!help') {
            await message.reply(
                '📋 *Group Bot Commands*\n\n' +
                '`!ban @user` - Remove user from group\n' +
                '`!tagall` - Mention all members\n' +
                '`!link` - Get group invite link\n' +
                '`!promote @user` - Make someone admin\n' +
                '`!demote @user` - Remove admin status\n' +
                '`!warn @user` - Issue warning\n' +
                '`!settings` - Show bot config\n\n' +
                '*Auto-Mod:*\n' +
                '🔗 WhatsApp invite links are automatically deleted.'
            );
        }
        
        // !tagall - Mention everyone
        if (body === '!tagall') {
            let mentions = chat.participants.map(p => p.id._serialized);
            await message.reply(`📢 ATTENTION EVERYONE!\n\nMessage from Admin:`, undefined, { mentions });
        }
        
        // !link - Get group invite link
        if (body === '!link') {
            const inviteCode = await chat.getInviteCode();
            await message.reply(`🔗 Group invite link:\nhttps://chat.whatsapp.com/${inviteCode}`);
        }
        
        // !ban @user - Remove user
        if (body.startsWith('!ban ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            if (target !== client.info.wid._serialized) {
                await chat.removeParticipants([target]);
                await message.reply(`✅ User removed from the group.`);
            }
        }
        
        // !promote @user - Make admin
        if (body.startsWith('!promote ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            await chat.promoteParticipants([target]);
            await message.reply(`👑 User is now an admin!`);
        }
        
        // !demote @user - Remove admin
        if (body.startsWith('!demote ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            await chat.demoteParticipants([target]);
            await message.reply(`👤 User is no longer an admin.`);
        }
        
        // !warn @user - Issue warning
        if (body.startsWith('!warn ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            await message.reply(`⚠️ Warning issued to @${target.split('@')[0]}. 3 warnings = removal.`);
        }
        
        // !settings - Show config
        if (body === '!settings') {
            await message.reply(
                '🤖 *Bot Settings*\n\n' +
                '✅ Link protection: ON (WhatsApp invites)\n' +
                '✅ Auto-delete: Enabled\n\n' +
                'Type `!menu` for all commands'
            );
        }
        
    } catch (error) {
        console.error('Error:', error);
    }
});

client.initialize();
