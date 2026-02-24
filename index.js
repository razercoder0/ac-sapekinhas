const { Client, GatewayIntentBits, ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder } = require('discord.js');
const express = require('express');
const crypto  = require('crypto');

// ---- CONFIG -----------------------------------------------------------------
const BOT_TOKEN      = process.env.BOT_TOKEN;       // token do bot
const CHANNEL_ID     = process.env.CHANNEL_ID;      // canal onde aparecem os pedidos
const ADMIN_ROLE_ID  = process.env.ADMIN_ROLE_ID;   // role de admin no discord
const API_SECRET     = process.env.API_SECRET;      // chave secreta pra assinar requests
const PORT           = process.env.PORT || 3000;
// -----------------------------------------------------------------------------

const client  = new Client({ intents: [GatewayIntentBits.Guilds] });
const app     = express();
app.use(express.json());

// Banco em memoria (substitui por um JSON file ou DB se quiser persistencia)
// { hwid: { status: 'pending'|'approved'|'denied', messageId, userId, nick } }
const db = new Map();

// ---- Gera token de sessao pro HWID aprovado ---------------------------------
function generateToken(hwid) {
    return crypto.createHmac('sha256', API_SECRET).update(hwid).digest('hex').substring(0, 32);
}

// ---- Verifica assinatura do injector ----------------------------------------
function verifySignature(body, sig) {
    const expected = crypto.createHmac('sha256', API_SECRET)
        .update(JSON.stringify(body)).digest('hex');
    return expected === sig;
}

// ---- ROTAS DA API -----------------------------------------------------------

// Injector chama isso primeiro pra pedir acesso
app.post('/request', async (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req.body, sig)) return res.status(401).json({ error: 'Assinatura invalida' });

    const { hwid, nick } = req.body;
    if (!hwid || !nick) return res.status(400).json({ error: 'Faltando hwid ou nick' });

    // Se ja aprovado, retorna token direto
    const existing = db.get(hwid);
    if (existing?.status === 'approved') {
        return res.json({ status: 'approved', token: generateToken(hwid) });
    }
    if (existing?.status === 'pending') {
        return res.json({ status: 'pending' });
    }
    if (existing?.status === 'denied') {
        return res.json({ status: 'denied' });
    }

    // Novo pedido — manda pro Discord
    try {
        const channel = await client.channels.fetch(CHANNEL_ID);

        const embed = new EmbedBuilder()
            .setTitle('🔔 Novo pedido de acesso')
            .setColor(0x8B00FF)
            .addFields(
                { name: 'Nick',  value: nick,  inline: true },
                { name: 'HWID',  value: `\`${hwid}\``, inline: false },
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
        res.json({ status: 'pending' });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

// Injector fica polling aqui esperando resposta
app.post('/check', (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req.body, sig)) return res.status(401).json({ error: 'Assinatura invalida' });

    const { hwid } = req.body;
    const entry = db.get(hwid);

    if (!entry) return res.json({ status: 'unknown' });
    if (entry.status === 'approved') return res.json({ status: 'approved', token: generateToken(hwid) });
    return res.json({ status: entry.status });
});

// Admin pode revogar via Discord ou via essa rota
app.post('/revoke', (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req.body, sig)) return res.status(401).json({ error: 'Assinatura invalida' });

    const { hwid } = req.body;
    if (db.has(hwid)) {
        db.get(hwid).status = 'denied';
        return res.json({ ok: true });
    }
    res.status(404).json({ error: 'HWID nao encontrado' });
});

// Injector verifica se token ainda e valido (polling de 30s pra detectar revogacao)
app.post('/verify', (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req.body, sig)) return res.status(401).json({ error: 'Assinatura invalida' });

    const { hwid, token } = req.body;
    const entry = db.get(hwid);

    if (!entry || entry.status !== 'approved') return res.json({ valid: false });
    if (generateToken(hwid) !== token)          return res.json({ valid: false });
    return res.json({ valid: true });
});

// ---- INTERACOES DO BOT ------------------------------------------------------
client.on('interactionCreate', async interaction => {
    if (!interaction.isButton()) return;

    // Checa se quem clicou tem a role de admin
    const member = interaction.member;
    if (!member.roles.cache.has(ADMIN_ROLE_ID)) {
        return interaction.reply({ content: '❌ Sem permissao!', ephemeral: true });
    }

    const [action, ...hwidParts] = interaction.customId.split('_');
    const hwid = hwidParts.join('_');
    const entry = db.get(hwid);
    if (!entry) return interaction.reply({ content: '❌ Pedido nao encontrado!', ephemeral: true });

    if (action === 'approve') {
        entry.status = 'approved';

        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setCustomId(`approve_${hwid}`)
                .setLabel('✅ Aprovado')
                .setStyle(ButtonStyle.Success)
                .setDisabled(true),
            new ButtonBuilder()
                .setCustomId(`deny_${hwid}`)
                .setLabel('❌ Negar')
                .setStyle(ButtonStyle.Danger)
                .setDisabled(true),
            new ButtonBuilder()
                .setCustomId(`revoke_${hwid}`)
                .setLabel('🔒 Revogar acesso')
                .setStyle(ButtonStyle.Danger)
                .setDisabled(false)
        );

        await interaction.update({ components: [row] });
        await interaction.followUp({ content: `✅ **${entry.nick}** aprovado por <@${interaction.user.id}>`, ephemeral: false });

    } else if (action === 'deny') {
        entry.status = 'denied';

        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`approve_${hwid}`).setLabel('✅ Aprovar').setStyle(ButtonStyle.Success).setDisabled(true),
            new ButtonBuilder().setCustomId(`deny_${hwid}`).setLabel('❌ Negado').setStyle(ButtonStyle.Danger).setDisabled(true),
            new ButtonBuilder().setCustomId(`revoke_${hwid}`).setLabel('🔒 Revogar').setStyle(ButtonStyle.Secondary).setDisabled(true)
        );

        await interaction.update({ components: [row] });
        await interaction.followUp({ content: `❌ **${entry.nick}** negado por <@${interaction.user.id}>`, ephemeral: false });

    } else if (action === 'revoke') {
        entry.status = 'denied';

        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`approve_${hwid}`).setLabel('✅ Aprovar').setStyle(ButtonStyle.Success).setDisabled(true),
            new ButtonBuilder().setCustomId(`deny_${hwid}`).setLabel('❌ Negar').setStyle(ButtonStyle.Danger).setDisabled(true),
            new ButtonBuilder().setCustomId(`revoke_${hwid}`).setLabel('🔒 Revogado').setStyle(ButtonStyle.Danger).setDisabled(true)
        );

        await interaction.update({ components: [row] });
        await interaction.followUp({ content: `🔒 Acesso de **${entry.nick}** revogado por <@${interaction.user.id}>`, ephemeral: false });
    }
});

// ---- START ------------------------------------------------------------------
client.once('ready', () => {
    console.log(`Bot online: ${client.user.tag}`);
});

app.listen(PORT, () => console.log(`API rodando na porta ${PORT}`));
client.login(BOT_TOKEN);