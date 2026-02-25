const { Client, GatewayIntentBits, ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder } = require('discord.js');
const express = require('express');
const crypto  = require('crypto');

// ---- CONFIG -----------------------------------------------------------------
const BOT_TOKEN      = process.env.BOT_TOKEN;
const CHANNEL_ID     = process.env.CHANNEL_ID;
const ADMIN_ROLE_ID  = process.env.ADMIN_ROLE_ID;
const API_SECRET     = process.env.API_SECRET;
const PORT           = process.env.PORT || 3000;
// -----------------------------------------------------------------------------

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const app    = express();

// ⚠️  IMPORTANTE: guarda o raw body ANTES do express parsear o JSON
//     Isso garante que a assinatura bate com o que o injector mandou
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

const db = new Map();
// { hwid: { status: 'pending'|'approved'|'denied', messageId, nick } }

// ---- Helpers ----------------------------------------------------------------
function generateToken(hwid) {
    return crypto.createHmac('sha256', API_SECRET).update(hwid).digest('hex').substring(0, 32);
}

function verifySignature(req, sig) {
    if (!sig || !req.rawBody) return false;
    const expected = crypto
        .createHmac('sha256', API_SECRET)
        .update(req.rawBody)   // assina o body RAW, igual ao injector
        .digest('hex');
    return expected === sig;
}

// ---- Rotas ------------------------------------------------------------------

app.post('/request', async (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) {
        console.log('[/request] Assinatura invalida');
        return res.status(401).json({ error: 'Assinatura invalida' });
    }

    const { hwid, nick } = req.body;
    if (!hwid || !nick) return res.status(400).json({ error: 'Faltando hwid ou nick' });

    const existing = db.get(hwid);
    if (existing?.status === 'approved') return res.json({ status: 'approved', token: generateToken(hwid) });
    if (existing?.status === 'pending')  return res.json({ status: 'pending' });
    if (existing?.status === 'denied')   return res.json({ status: 'denied' });

    try {
        const channel = await client.channels.fetch(CHANNEL_ID);

        const embed = new EmbedBuilder()
            .setTitle('🔔 Novo pedido de acesso')
            .setColor(0x8B00FF)
            .addFields(
                { name: 'Nick', value: nick,         inline: true  },
                { name: 'HWID', value: `\`${hwid}\``, inline: false }
            )
            .setTimestamp();

        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setCustomId(`approve_${hwid}`)
                .setLabel('✅ Aprovar')
                .setStyle(ButtonStyle.Success),
            new ButtonBuilder()
                .setCustomId(`deny_${hwid}`)
                .setLabel('❌ Negar')
                .setStyle(ButtonStyle.Danger),
            new ButtonBuilder()
                .setCustomId(`revoke_${hwid}`)
                .setLabel('🔒 Revogar')
                .setStyle(ButtonStyle.Secondary)
                .setDisabled(true)
        );

        const msg = await channel.send({ embeds: [embed], components: [row] });
        db.set(hwid, { status: 'pending', messageId: msg.id, nick });
        console.log(`[/request] Pedido enviado pro Discord — nick: ${nick}, hwid: ${hwid}`);
        res.json({ status: 'pending' });

    } catch (e) {
        console.error('[/request] Erro ao mandar msg no Discord:', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.post('/check', (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) return res.status(401).json({ error: 'Assinatura invalida' });

    const { hwid } = req.body;
    const entry = db.get(hwid);

    if (!entry)                        return res.json({ status: 'unknown' });
    if (entry.status === 'approved')   return res.json({ status: 'approved', token: generateToken(hwid) });
    return res.json({ status: entry.status });
});

app.post('/revoke', (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) return res.status(401).json({ error: 'Assinatura invalida' });

    const { hwid } = req.body;
    if (db.has(hwid)) {
        db.get(hwid).status = 'denied';
        return res.json({ ok: true });
    }
    res.status(404).json({ error: 'HWID nao encontrado' });
});

app.post('/verify', (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) return res.status(401).json({ error: 'Assinatura invalida' });

    const { hwid, token } = req.body;
    const entry = db.get(hwid);

    if (!entry || entry.status !== 'approved') return res.json({ valid: false });
    if (generateToken(hwid) !== token)          return res.json({ valid: false });
    return res.json({ valid: true });
});

// ---- Interacoes do bot ------------------------------------------------------
client.on('interactionCreate', async interaction => {
    if (!interaction.isButton()) return;

    const member = interaction.member;
    if (!member.roles.cache.has(ADMIN_ROLE_ID)) {
        return interaction.reply({ content: '❌ Sem permissao!', ephemeral: true });
    }

    const [action, ...hwidParts] = interaction.customId.split('_');
    const hwid  = hwidParts.join('_');
    const entry = db.get(hwid);
    if (!entry) return interaction.reply({ content: '❌ Pedido nao encontrado!', ephemeral: true });

    if (action === 'approve') {
        entry.status = 'approved';
        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`approve_${hwid}`).setLabel('✅ Aprovado').setStyle(ButtonStyle.Success).setDisabled(true),
            new ButtonBuilder().setCustomId(`deny_${hwid}`).setLabel('❌ Negar').setStyle(ButtonStyle.Danger).setDisabled(true),
            new ButtonBuilder().setCustomId(`revoke_${hwid}`).setLabel('🔒 Revogar acesso').setStyle(ButtonStyle.Danger).setDisabled(false)
        );
        await interaction.update({ components: [row] });
        await interaction.followUp({ content: `✅ **${entry.nick}** aprovado por <@${interaction.user.id}>` });

    } else if (action === 'deny') {
        entry.status = 'denied';
        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`approve_${hwid}`).setLabel('✅ Aprovar').setStyle(ButtonStyle.Success).setDisabled(true),
            new ButtonBuilder().setCustomId(`deny_${hwid}`).setLabel('❌ Negado').setStyle(ButtonStyle.Danger).setDisabled(true),
            new ButtonBuilder().setCustomId(`revoke_${hwid}`).setLabel('🔒 Revogar').setStyle(ButtonStyle.Secondary).setDisabled(true)
        );
        await interaction.update({ components: [row] });
        await interaction.followUp({ content: `❌ **${entry.nick}** negado por <@${interaction.user.id}>` });

    } else if (action === 'revoke') {
        entry.status = 'denied';
        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`approve_${hwid}`).setLabel('✅ Aprovar').setStyle(ButtonStyle.Success).setDisabled(true),
            new ButtonBuilder().setCustomId(`deny_${hwid}`).setLabel('❌ Negar').setStyle(ButtonStyle.Danger).setDisabled(true),
            new ButtonBuilder().setCustomId(`revoke_${hwid}`).setLabel('🔒 Revogado').setStyle(ButtonStyle.Danger).setDisabled(true)
        );
        await interaction.update({ components: [row] });
        await interaction.followUp({ content: `🔒 Acesso de **${entry.nick}** revogado por <@${interaction.user.id}>` });
    }
});

// ---- Start ------------------------------------------------------------------
client.once('ready', () => console.log(`Bot online: ${client.user.tag}`));
app.listen(PORT, () => console.log(`API rodando na porta ${PORT}`));
client.login(BOT_TOKEN);
