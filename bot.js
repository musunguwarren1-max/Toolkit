const { Client } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');

const client = new Client();

client.on('qr', qr => {
    qrcode.generate(qr, {small: true});
    console.log('Scan the QR code with WhatsApp');
});

client.on('ready', () => {
    console.log('Bot is running!');
});

client.on('message', async (message) => {
    const chat = await message.getChat();
    
    // Auto-delete invite links
    if (message.body.includes('chat.whatsapp.com')) {
        await message.delete();
        await message.reply('❌ Invite links not allowed');
    }
});

client.initialize();
