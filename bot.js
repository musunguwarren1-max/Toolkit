const { Client, LocalAuth } = require('whatsapp-web.js');

// ============================================
// REPLACE THIS WITH YOUR PHONE NUMBER
// Format: just digits, no +, no spaces
// Example: "12345678900"
// ============================================
const MY_PHONE_NUMBER = "254102776096";  // <----- CHANGE THIS!

// ============================================
// INITIALIZE CLIENT WITH FIXED AUTH PATH
// ============================================
const client = new Client({
    authStrategy: new LocalAuth({ 
        dataPath: "./auth",           // Now uses /app/auth (writable)
        clientId: "whatsapp-bot"      // Unique ID for this bot
    }),
    puppeteer: {
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--disable-gpu'
        ]
    },
    // Enable pairing code instead of QR
    pairWithPhoneNumber: {
        phoneNumber: MY_PHONE_NUMBER,
        showNotification: true,
        intervalMs: 180000
    }
});

// ============================================
// EVENT HANDLERS
// ============================================

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
    console.log('✅ Bot authenticated successfully!');
});

client.on('ready', () => {
    console.log('🚀 WhatsApp Group Bot is running!');
    console.log('Bot will now auto-delete invite links and respond to commands');
});

client.on('auth_failure', (msg) => {
    console.error('❌ Authentication failed:', msg);
});

client.on('disconnected', (reason) => {
    console.log('⚠️ Bot disconnected:', reason);
    console.log('Bot will attempt to reconnect...');
});

// ============================================
// GROUP MANAGEMENT FEATURES
// ============================================

// Store warnings for users (in memory, resets on restart)
let warnings = new Map();

client.on('message', async (message) => {
    try {
        const chat = await message.getChat();
        
        // Only process group messages
        if (!chat.isGroup) return;
        
        const sender = message.author || message.from;
        const senderName = sender.split('@')[0];
        const body = message.body;
        const lowerBody = body.toLowerCase();
        
        // Check if sender is admin
        const participant = chat.participants.find(p => p.id._serialized === sender);
        const isAdmin = participant?.isAdmin || participant?.isSuperAdmin || false;
        
        // ============================================
        // AUTO-DELETE WHATSAPP INVITE LINKS
        // ============================================
        const inviteLinkPattern = /chat\.whatsapp\.com\/[A-Za-z0-9]{22}/;
        if (inviteLinkPattern.test(body)) {
            await message.delete();
            await client.sendMessage(chat.id._serialized, 
                `⚠️ @${senderName}, invite links are not allowed in this group!`, 
                { mentions: [sender] });
            console.log(`🗑️ Deleted invite link from ${senderName}`);
            return;
        }
        
        // ============================================
        // COMMANDS (Admins Only)
        // ============================================
        if (!isAdmin) return;
        
        // !menu or !help - Show all commands
        if (lowerBody === '!menu' || lowerBody === '!help') {
            await message.reply(
                '📋 *GROUP BOT COMMANDS*\n\n' +
                '*Admin Commands:*\n' +
                '`!ban @user` - Remove user from group\n' +
                '`!tagall` - Mention all members\n' +
                '`!link` - Get group invite link\n' +
                '`!promote @user` - Make someone admin\n' +
                '`!demote @user` - Remove admin status\n' +
                '`!warn @user` - Issue warning (3 warnings = ban)\n' +
                '`!warnings @user` - Check user warnings\n' +
                '`!clearwarn @user` - Clear warnings\n' +
                '`!settings` - Show bot config\n\n' +
                '*Auto-Moderation:*\n' +
                '🔗 WhatsApp invite links are automatically deleted'
            );
        }
        
        // !tagall - Mention everyone
        else if (lowerBody === '!tagall') {
            let mentions = chat.participants.map(p => p.id._serialized);
            let mentionText = chat.participants.map(p => `@${p.id._serialized.split('@')[0]}`).join(' ');
            await message.reply(`📢 *ATTENTION EVERYONE!*\n\n${mentionText}\n\n_Message from Admin_`, undefined, { mentions });
            console.log(`📢 Tagall used by ${senderName}`);
        }
        
        // !link - Get group invite link
        else if (lowerBody === '!link') {
            try {
                const inviteCode = await chat.getInviteCode();
                await message.reply(`🔗 *Group Invite Link*\n\nhttps://chat.whatsapp.com/${inviteCode}`);
            } catch (error) {
                await message.reply(`❌ Failed to get invite link. Make sure I'm an admin.`);
            }
        }
        
        // !ban @user - Remove user
        else if (lowerBody.startsWith('!ban ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            const targetName = target.split('@')[0];
            
            if (target === client.info.wid._serialized) {
                await message.reply(`❌ I cannot ban myself!`);
            } else {
                try {
                    await chat.removeParticipants([target]);
                    await message.reply(`✅ User @${targetName} has been removed from the group.`);
                    console.log(`🔨 ${senderName} banned ${targetName}`);
                } catch (error) {
                    await message.reply(`❌ Failed to ban user. Make sure I'm an admin.`);
                }
            }
        }
        
        // !promote @user - Make admin
        else if (lowerBody.startsWith('!promote ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            const targetName = target.split('@')[0];
            
            try {
                await chat.promoteParticipants([target]);
                await message.reply(`👑 @${targetName} is now an admin!`);
                console.log(`⬆️ ${senderName} promoted ${targetName}`);
            } catch (error) {
                await message.reply(`❌ Failed to promote user. Make sure I'm an admin.`);
            }
        }
        
        // !demote @user - Remove admin
        else if (lowerBody.startsWith('!demote ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            const targetName = target.split('@')[0];
            
            try {
                await chat.demoteParticipants([target]);
                await message.reply(`👤 @${targetName} is no longer an admin.`);
                console.log(`⬇️ ${senderName} demoted ${targetName}`);
            } catch (error) {
                await message.reply(`❌ Failed to demote user. Make sure I'm an admin.`);
            }
        }
        
        // !warn @user - Issue warning
        else if (lowerBody.startsWith('!warn ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            const targetName = target.split('@')[0];
            const warningKey = `${chat.id._serialized}_${target}`;
            
            let currentWarnings = warnings.get(warningKey) || 0;
            currentWarnings++;
            warnings.set(warningKey, currentWarnings);
            
            await message.reply(
                `⚠️ *WARNING #${currentWarnings}/3* for @${targetName}\n\n` +
                (currentWarnings >= 3 ? `🚫 User will be removed!` : `_Next warning = removal_`)
            );
            
            console.log(`⚠️ ${senderName} warned ${targetName} (${currentWarnings}/3)`);
            
            // Auto-ban after 3 warnings
            if (currentWarnings >= 3) {
                try {
                    await chat.removeParticipants([target]);
                    await message.reply(`🚫 @${targetName} has been removed for reaching 3 warnings.`);
                    warnings.delete(warningKey);
                } catch (error) {
                    await message.reply(`❌ Failed to remove user.`);
                }
            }
        }
        
        // !warnings @user - Check warnings
        else if (lowerBody.startsWith('!warnings ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            const targetName = target.split('@')[0];
            const warningKey = `${chat.id._serialized}_${target}`;
            const currentWarnings = warnings.get(warningKey) || 0;
            await message.reply(`📊 @${targetName} has *${currentWarnings}/3* warnings.`);
        }
        
        // !clearwarn @user - Clear warnings
        else if (lowerBody.startsWith('!clearwarn ') && message.mentionedIds.length > 0) {
            const target = message.mentionedIds[0];
            const targetName = target.split('@')[0];
            const warningKey = `${chat.id._serialized}_${target}`;
            warnings.delete(warningKey);
            await message.reply(`✅ Warnings cleared for @${targetName}.`);
        }
        
        // !settings - Show config
        else if (lowerBody === '!settings') {
            await message.reply(
                '🤖 *BOT SETTINGS*\n\n' +
                '🔗 Auto-delete invite links: ✅ ACTIVE\n' +
                '⚠️ Warning limit: 3 warnings = auto-ban\n\n' +
                'Type `!menu` for all commands'
            );
        }
        
    } catch (error) {
        console.error('Error handling message:', error);
    }
});

// ============================================
// START THE BOT
// ============================================
client.initialize();

console.log('🤖 Starting WhatsApp Group Bot...');
console.log('Waiting for pairing code...\n');
