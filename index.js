const {
    Client, GatewayIntentBits, ActionRowBuilder, ButtonBuilder,
    ButtonStyle, EmbedBuilder, SlashCommandBuilder, REST, Routes,
    PermissionFlagsBits
} = require('discord.js');
const express = require('express');
const crypto  = require('crypto');
const fs      = require('fs');
const https   = require('https');

// ── CONFIG ────────────────────────────────────────────────────────────────────
const BOT_TOKEN     = process.env.BOT_TOKEN;
const CLIENT_ID     = process.env.CLIENT_ID;
const GUILD_ID      = process.env.GUILD_ID;
const CHANNEL_ID    = process.env.CHANNEL_ID;
const LOG_CHANNEL   = process.env.LOG_CHANNEL_ID;
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID;
const API_SECRET    = process.env.API_SECRET;
const PORT          = process.env.PORT || 3000;
const DB_FILE       = './db.json';

// ⚠️  Coloca a URL do seu serviço na Render aqui pra manter vivo
// Ex: "ac-sapekinhas.onrender.com"
const SELF_URL = process.env.SELF_URL || null;
// ─────────────────────────────────────────────────────────────────────────────

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const app    = express();

app.use(express.json({
    verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

// ── KEEP-ALIVE: pinga o próprio servidor a cada 10min p/ não dormir ──────────
function startKeepAlive() {
    if (!SELF_URL) {
        console.log('⚠️  SELF_URL não configurado — servidor pode dormir na Render free!');
        return;
    }
    setInterval(() => {
        https.get(`https://${SELF_URL}/ping`, res => {
            console.log(`[keep-alive] ping → ${res.statusCode}`);
        }).on('error', e => {
            console.error('[keep-alive] erro:', e.message);
        });
    }, 10 * 60 * 1000); // a cada 10 minutos
    console.log(`✅ Keep-alive ativo → https://${SELF_URL}/ping`);
}

// Rota do ping
app.get('/ping', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ── BANCO JSON ────────────────────────────────────────────────────────────────
function loadDB() {
    try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
    catch { return { users: {} }; }
}
function saveDB(db) {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function generateToken(hwid) {
    return crypto.createHmac('sha256', API_SECRET).update(hwid).digest('hex').substring(0, 32);
}
function verifySignature(req, sig) {
    if (!sig || !req.rawBody) return false;
    const expected = crypto.createHmac('sha256', API_SECRET).update(req.rawBody).digest('hex');
    return expected === sig;
}
function isAdmin(member) {
    return member.roles.cache.has(ADMIN_ROLE_ID) ||
           member.permissions.has(PermissionFlagsBits.Administrator);
}
function now() { return new Date().toISOString(); }
function fmtDate(iso) {
    if (!iso) return '—';
    return `<t:${Math.floor(new Date(iso).getTime() / 1000)}:f>`;
}
function statusEmoji(s) {
    return { approved: '🟢', denied: '🔴', pending: '🟡' }[s] ?? '⚪';
}
async function sendLog(guild, embed) {
    if (!LOG_CHANNEL) return;
    try { await (await client.channels.fetch(LOG_CHANNEL)).send({ embeds: [embed] }); } catch {}
}
function buildRequestRow(hwid, approved = false, denied = false) {
    return new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`approve_${hwid}`).setLabel('Aprovar').setEmoji('✅').setStyle(ButtonStyle.Success).setDisabled(approved || denied),
        new ButtonBuilder().setCustomId(`deny_${hwid}`).setLabel('Negar').setEmoji('❌').setStyle(ButtonStyle.Danger).setDisabled(approved || denied),
        new ButtonBuilder().setCustomId(`revoke_${hwid}`).setLabel('Revogar').setEmoji('🔒').setStyle(ButtonStyle.Secondary).setDisabled(!approved)
    );
}
function findUser(db, query) {
    query = query.toLowerCase();
    return Object.values(db.users).find(u =>
        u.nick?.toLowerCase() === query || u.hwid?.toLowerCase() === query
    ) || null;
}

// ── SLASH COMMANDS ────────────────────────────────────────────────────────────
const commands = [
    new SlashCommandBuilder().setName('online').setDescription('Usuários com sessão ativa agora'),
    new SlashCommandBuilder().setName('lista').setDescription('Lista usuários por status')
        .addStringOption(o => o.setName('status').setDescription('Filtro').setRequired(false)
            .addChoices(
                { name: '✅ Aprovados', value: 'approved' },
                { name: '❌ Negados',   value: 'denied'   },
                { name: '🟡 Pendentes', value: 'pending'  },
                { name: '📋 Todos',     value: 'all'      }
            )),
    new SlashCommandBuilder().setName('info').setDescription('Info detalhada de um usuário')
        .addStringOption(o => o.setName('nick').setDescription('Nick ou HWID').setRequired(true)),
    new SlashCommandBuilder().setName('aprovar').setDescription('Aprova manualmente um usuário')
        .addStringOption(o => o.setName('nick').setDescription('Nick ou HWID').setRequired(true))
        .addStringOption(o => o.setName('motivo').setDescription('Motivo').setRequired(false)),
    new SlashCommandBuilder().setName('negar').setDescription('Nega manualmente um usuário')
        .addStringOption(o => o.setName('nick').setDescription('Nick ou HWID').setRequired(true))
        .addStringOption(o => o.setName('motivo').setDescription('Motivo').setRequired(false)),
    new SlashCommandBuilder().setName('revogar').setDescription('Revoga acesso de um usuário aprovado')
        .addStringOption(o => o.setName('nick').setDescription('Nick ou HWID').setRequired(true))
        .addStringOption(o => o.setName('motivo').setDescription('Motivo').setRequired(false)),
    new SlashCommandBuilder().setName('desrevogar').setDescription('Remove banimento e volta pra pendente')
        .addStringOption(o => o.setName('nick').setDescription('Nick ou HWID').setRequired(true))
        .addStringOption(o => o.setName('motivo').setDescription('Motivo').setRequired(false)),
    new SlashCommandBuilder().setName('historico').setDescription('Histórico completo de um usuário')
        .addStringOption(o => o.setName('nick').setDescription('Nick ou HWID').setRequired(true)),
    new SlashCommandBuilder().setName('stats').setDescription('Estatísticas gerais do sistema'),
    new SlashCommandBuilder().setName('limpar').setDescription('Remove usuário do banco')
        .addStringOption(o => o.setName('nick').setDescription('Nick ou HWID').setRequired(true)),
];

async function registerCommands() {
    const rest = new REST({ version: '10' }).setToken(BOT_TOKEN);
    try {
        await rest.put(Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID), {
            body: commands.map(c => c.toJSON())
        });
        console.log('✅ Slash commands registrados!');
    } catch (e) { console.error('❌ Erro ao registrar commands:', e); }
}

// ── INTERACTIONS ──────────────────────────────────────────────────────────────
client.on('interactionCreate', async interaction => {

    // ── BOTÕES ────────────────────────────────────────────────────────────────
    if (interaction.isButton()) {
        if (!isAdmin(interaction.member))
            return interaction.reply({ content: '❌ Sem permissão!', ephemeral: true });

        const [action, ...hwidParts] = interaction.customId.split('_');
        const hwid  = hwidParts.join('_');
        const db    = loadDB();
        const entry = db.users[hwid];
        if (!entry) return interaction.reply({ content: '❌ Não encontrado!', ephemeral: true });

        const adminTag = interaction.user.username;

        if (action === 'approve') {
            entry.status = 'approved'; entry.approvedAt = now(); entry.approvedBy = adminTag;
            entry.history.push({ action: 'approved', by: adminTag, at: now(), note: 'via botão' });
            saveDB(db);
            await interaction.update({ components: [buildRequestRow(hwid, true, false)] });
            await interaction.followUp({ content: `✅ **${entry.nick}** aprovado por <@${interaction.user.id}>` });
        } else if (action === 'deny') {
            entry.status = 'denied'; entry.deniedAt = now(); entry.deniedBy = adminTag;
            entry.history.push({ action: 'denied', by: adminTag, at: now(), note: 'via botão' });
            saveDB(db);
            await interaction.update({ components: [buildRequestRow(hwid, false, true)] });
            await interaction.followUp({ content: `❌ **${entry.nick}** negado por <@${interaction.user.id}>` });
        } else if (action === 'revoke') {
            entry.status = 'denied'; entry.revokedAt = now(); entry.revokedBy = adminTag;
            entry.history.push({ action: 'revoked', by: adminTag, at: now(), note: 'via botão' });
            saveDB(db);
            await interaction.update({ components: [buildRequestRow(hwid, false, true)] });
            await interaction.followUp({ content: `🔒 Acesso de **${entry.nick}** revogado por <@${interaction.user.id}>` });
        }

        await sendLog(interaction.guild, new EmbedBuilder()
            .setTitle({ approve:'✅ Aprovado', deny:'❌ Negado', revoke:'🔒 Revogado' }[action] ?? 'Ação')
            .setColor({ approve:0x00cc44, deny:0xcc2200, revoke:0xff6600 }[action] ?? 0x888888)
            .addFields(
                { name:'Nick', value:entry.nick, inline:true },
                { name:'Admin', value:adminTag,  inline:true },
                { name:'HWID',  value:`\`${hwid}\`` }
            ).setTimestamp());
        return;
    }

    // ── SLASH COMMANDS ────────────────────────────────────────────────────────
    if (!interaction.isChatInputCommand()) return;
    if (!isAdmin(interaction.member))
        return interaction.reply({ content: '❌ Sem permissão!', ephemeral: true });

    const db  = loadDB();
    const cmd = interaction.commandName;

    if (cmd === 'online') {
        const threshold = 5 * 60 * 1000;
        const active = Object.values(db.users).filter(u =>
            u.status === 'approved' && u.lastSeen &&
            Date.now() - new Date(u.lastSeen).getTime() < threshold
        );
        return interaction.reply({ embeds: [new EmbedBuilder()
            .setTitle('🟢 Usuários Online Agora').setColor(0x00cc44)
            .setDescription(active.length === 0 ? '*Ninguém online.*' :
                active.map(u => `• **${u.nick}** — visto ${fmtDate(u.lastSeen)} | Sessões: ${u.sessions}`).join('\n'))
            .setFooter({ text: `Total: ${active.length}` }).setTimestamp()] });
    }

    if (cmd === 'lista') {
        const filter   = interaction.options.getString('status') || 'all';
        const all      = Object.values(db.users);
        const filtered = filter === 'all' ? all : all.filter(u => u.status === filter);
        if (filtered.length === 0)
            return interaction.reply({ content: `Nenhum usuário com status **${filter}**.`, ephemeral: true });

        const lines = filtered.map(u => `${statusEmoji(u.status)} **${u.nick}** — ${fmtDate(u.requestedAt)}`);
        const chunks = [];
        let chunk = '';
        for (const l of lines) {
            if (chunk.length + l.length + 1 > 3800) { chunks.push(chunk); chunk = ''; }
            chunk += l + '\n';
        }
        if (chunk) chunks.push(chunk);
        await interaction.reply({ embeds: [new EmbedBuilder()
            .setTitle(`📋 Lista — ${filter === 'all' ? 'Todos' : filter}`).setColor(0x8800ff)
            .setDescription(chunks[0]).setFooter({ text: `Total: ${filtered.length}` }).setTimestamp()] });
        for (let i = 1; i < chunks.length; i++)
            await interaction.followUp({ embeds: [new EmbedBuilder().setColor(0x8800ff).setDescription(chunks[i])] });
        return;
    }

    if (cmd === 'info') {
        const u = findUser(db, interaction.options.getString('nick'));
        if (!u) return interaction.reply({ content: '❌ Não encontrado!', ephemeral: true });
        return interaction.reply({ embeds: [new EmbedBuilder()
            .setTitle(`👤 Info — ${u.nick}`)
            .setColor({ approved:0x00cc44, denied:0xcc2200, pending:0xffcc00 }[u.status] ?? 0x888888)
            .addFields(
                { name:'Status',       value:`${statusEmoji(u.status)} ${u.status}`, inline:true },
                { name:'Sessões',      value:`${u.sessions}`,                        inline:true },
                { name:'Último login', value:fmtDate(u.lastSeen),                   inline:true },
                { name:'HWID',         value:`\`${u.hwid}\``,                       inline:false },
                { name:'Pedido em',    value:fmtDate(u.requestedAt),                inline:true  },
                { name:'Aprovado em',  value:fmtDate(u.approvedAt),                 inline:true  },
                { name:'Aprovado por', value:u.approvedBy || '—',                   inline:true  },
                { name:'Negado em',    value:fmtDate(u.deniedAt),                   inline:true  },
                { name:'Revogado em',  value:fmtDate(u.revokedAt),                  inline:true  },
                { name:'Revogado por', value:u.revokedBy || '—',                   inline:true  },
            ).setTimestamp()] });
    }

    if (cmd === 'aprovar') {
        const u = findUser(db, interaction.options.getString('nick'));
        const motivo = interaction.options.getString('motivo') || '—';
        if (!u) return interaction.reply({ content: '❌ Não encontrado!', ephemeral: true });
        const adminTag = interaction.user.username;
        Object.assign(u, { status:'approved', approvedAt:now(), approvedBy:adminTag, deniedAt:null, revokedAt:null });
        u.history.push({ action:'approved', by:adminTag, at:now(), note:motivo });
        saveDB(db);
        await sendLog(interaction.guild, new EmbedBuilder().setTitle('✅ Aprovação Manual').setColor(0x00cc44)
            .addFields({ name:'Nick', value:u.nick, inline:true }, { name:'Admin', value:adminTag, inline:true }, { name:'Motivo', value:motivo }).setTimestamp());
        return interaction.reply({ embeds: [new EmbedBuilder().setTitle('✅ Aprovado').setColor(0x00cc44)
            .setDescription(`**${u.nick}** aprovado!\nMotivo: ${motivo}`)] });
    }

    if (cmd === 'negar') {
        const u = findUser(db, interaction.options.getString('nick'));
        const motivo = interaction.options.getString('motivo') || '—';
        if (!u) return interaction.reply({ content: '❌ Não encontrado!', ephemeral: true });
        const adminTag = interaction.user.username;
        Object.assign(u, { status:'denied', deniedAt:now(), deniedBy:adminTag });
        u.history.push({ action:'denied', by:adminTag, at:now(), note:motivo });
        saveDB(db);
        await sendLog(interaction.guild, new EmbedBuilder().setTitle('❌ Negação Manual').setColor(0xcc2200)
            .addFields({ name:'Nick', value:u.nick, inline:true }, { name:'Admin', value:adminTag, inline:true }, { name:'Motivo', value:motivo }).setTimestamp());
        return interaction.reply({ embeds: [new EmbedBuilder().setTitle('❌ Negado').setColor(0xcc2200)
            .setDescription(`**${u.nick}** negado.\nMotivo: ${motivo}`)] });
    }

    if (cmd === 'revogar') {
        const u = findUser(db, interaction.options.getString('nick'));
        const motivo = interaction.options.getString('motivo') || '—';
        if (!u) return interaction.reply({ content: '❌ Não encontrado!', ephemeral: true });
        if (u.status !== 'approved')
            return interaction.reply({ content: `⚠️ **${u.nick}** não está aprovado.`, ephemeral: true });
        const adminTag = interaction.user.username;
        Object.assign(u, { status:'denied', revokedAt:now(), revokedBy:adminTag });
        u.history.push({ action:'revoked', by:adminTag, at:now(), note:motivo });
        saveDB(db);
        await sendLog(interaction.guild, new EmbedBuilder().setTitle('🔒 Revogação Manual').setColor(0xff6600)
            .addFields({ name:'Nick', value:u.nick, inline:true }, { name:'Admin', value:adminTag, inline:true }, { name:'Motivo', value:motivo }).setTimestamp());
        return interaction.reply({ embeds: [new EmbedBuilder().setTitle('🔒 Revogado').setColor(0xff6600)
            .setDescription(`Acesso de **${u.nick}** revogado.\nMotivo: ${motivo}`)] });
    }

    if (cmd === 'desrevogar') {
        const u = findUser(db, interaction.options.getString('nick'));
        const motivo = interaction.options.getString('motivo') || '—';
        if (!u) return interaction.reply({ content: '❌ Não encontrado!', ephemeral: true });
        const adminTag = interaction.user.username;
        Object.assign(u, { status:'pending', deniedAt:null, deniedBy:null, revokedAt:null, revokedBy:null });
        u.history.push({ action:'unrevoked', by:adminTag, at:now(), note:motivo });
        saveDB(db);
        await sendLog(interaction.guild, new EmbedBuilder().setTitle('🔓 Desrevogação').setColor(0x00aaff)
            .addFields({ name:'Nick', value:u.nick, inline:true }, { name:'Admin', value:adminTag, inline:true }, { name:'Motivo', value:motivo }).setTimestamp());
        return interaction.reply({ embeds: [new EmbedBuilder().setTitle('🔓 Banimento Removido').setColor(0x00aaff)
            .setDescription(`**${u.nick}** desrevogado — voltou pra pendente.\nMotivo: ${motivo}`)] });
    }

    if (cmd === 'historico') {
        const u = findUser(db, interaction.options.getString('nick'));
        if (!u) return interaction.reply({ content: '❌ Não encontrado!', ephemeral: true });
        const emoji = { approved:'✅', denied:'❌', revoked:'🔒', unrevoked:'🔓', inject:'💉', requested:'📥' };
        const lines = u.history.length === 0 ? ['*Sem histórico.*'] :
            u.history.slice(-25).map(h =>
                `${emoji[h.action] ?? '•'} **${h.action}** por \`${h.by}\` em ${fmtDate(h.at)}${h.note && h.note !== '—' ? `\n  ↳ ${h.note}` : ''}`
            );
        return interaction.reply({ embeds: [new EmbedBuilder()
            .setTitle(`📜 Histórico — ${u.nick}`).setColor(0x8800ff)
            .setDescription(lines.join('\n'))
            .setFooter({ text: `Total de eventos: ${u.history.length}` }).setTimestamp()] });
    }

    if (cmd === 'stats') {
        const all      = Object.values(db.users);
        const approved = all.filter(u => u.status === 'approved').length;
        const denied   = all.filter(u => u.status === 'denied').length;
        const pending  = all.filter(u => u.status === 'pending').length;
        const sessions = all.reduce((s, u) => s + (u.sessions || 0), 0);
        const online   = all.filter(u =>
            u.status === 'approved' && u.lastSeen &&
            Date.now() - new Date(u.lastSeen).getTime() < 5 * 60 * 1000
        ).length;
        return interaction.reply({ embeds: [new EmbedBuilder()
            .setTitle('📊 Estatísticas').setColor(0x8800ff)
            .addFields(
                { name:'🟢 Online',             value:`\`${online}\``,    inline:true },
                { name:'✅ Aprovados',           value:`\`${approved}\``,  inline:true },
                { name:'❌ Negados/Revogados',   value:`\`${denied}\``,    inline:true },
                { name:'🟡 Pendentes',           value:`\`${pending}\``,   inline:true },
                { name:'👥 Total cadastrados',   value:`\`${all.length}\``, inline:true },
                { name:'💉 Total sessões',       value:`\`${sessions}\``,  inline:true },
            ).setTimestamp()] });
    }

    if (cmd === 'limpar') {
        const u = findUser(db, interaction.options.getString('nick'));
        if (!u) return interaction.reply({ content: '❌ Não encontrado!', ephemeral: true });
        const nick = u.nick;
        delete db.users[u.hwid];
        saveDB(db);
        await sendLog(interaction.guild, new EmbedBuilder().setTitle('🗑️ Removido').setColor(0x888888)
            .addFields({ name:'Nick', value:nick, inline:true }, { name:'Admin', value:interaction.user.username, inline:true }).setTimestamp());
        return interaction.reply({ embeds: [new EmbedBuilder().setTitle('🗑️ Removido').setColor(0x888888)
            .setDescription(`**${nick}** removido do banco.`)] });
    }
});

// ── API ROUTES ────────────────────────────────────────────────────────────────
app.post('/request', async (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) {
        console.log('[/request] assinatura invalida');
        return res.status(401).json({ error: 'Assinatura invalida' });
    }

    const { hwid, nick } = req.body;
    if (!hwid || !nick) return res.status(400).json({ error: 'Faltando hwid ou nick' });

    const db       = loadDB();
    const existing = db.users[hwid];

    if (existing?.status === 'approved') return res.json({ status: 'approved', token: generateToken(hwid) });
    if (existing?.status === 'pending')  return res.json({ status: 'pending' });
    if (existing?.status === 'denied')   return res.json({ status: 'denied' });

    try {
        const channel = await client.channels.fetch(CHANNEL_ID);
        const embed   = new EmbedBuilder()
            .setTitle('🔔 Novo Pedido de Acesso').setColor(0x8800ff)
            .addFields({ name:'Nick', value:nick, inline:true }, { name:'HWID', value:`\`${hwid}\``, inline:false })
            .setTimestamp();

        const msg = await channel.send({ embeds: [embed], components: [buildRequestRow(hwid)] });

        db.users[hwid] = {
            hwid, nick, status: 'pending', messageId: msg.id, token: null,
            requestedAt: now(), approvedAt: null, approvedBy: null,
            deniedAt: null, deniedBy: null, revokedAt: null, revokedBy: null,
            sessions: 0, lastSeen: null,
            history: [{ action:'requested', by:nick, at:now(), note:'pedido inicial' }]
        };
        saveDB(db);
        console.log(`[/request] ${nick} | ${hwid}`);
        res.json({ status: 'pending' });
    } catch (e) {
        console.error('[/request] erro:', e);
        res.status(500).json({ error: 'Erro interno' });
    }
});

app.post('/check', (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) return res.status(401).json({ error: 'Assinatura invalida' });
    const { hwid } = req.body;
    const db    = loadDB();
    const entry = db.users[hwid];
    if (!entry)                      return res.json({ status: 'unknown' });
    if (entry.status === 'approved') return res.json({ status: 'approved', token: generateToken(hwid) });
    return res.json({ status: entry.status });
});

app.post('/verify', (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) return res.status(401).json({ error: 'Assinatura invalida' });
    const { hwid, token } = req.body;
    const db    = loadDB();
    const entry = db.users[hwid];
    if (!entry || entry.status !== 'approved') return res.json({ valid: false });
    if (generateToken(hwid) !== token)          return res.json({ valid: false });
    entry.lastSeen = now();
    entry.sessions = (entry.sessions || 0) + 1;
    entry.history.push({ action:'inject', by:entry.nick, at:now(), note:'sessão iniciada' });
    saveDB(db);
    return res.json({ valid: true });
});

app.post('/revoke', (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) return res.status(401).json({ error: 'Assinatura invalida' });
    const { hwid } = req.body;
    const db    = loadDB();
    const entry = db.users[hwid];
    if (!entry) return res.status(404).json({ error: 'HWID nao encontrado' });
    entry.status = 'denied'; entry.revokedAt = now(); entry.revokedBy = 'api';
    entry.history.push({ action:'revoked', by:'api', at:now(), note:'revogado via API' });
    saveDB(db);
    return res.json({ ok: true });
});

// ── START ─────────────────────────────────────────────────────────────────────
client.once('ready', async () => {
    console.log(`✅ Bot online: ${client.user.tag}`);
    await registerCommands();
    startKeepAlive();
});

app.listen(PORT, () => console.log(`✅ API na porta ${PORT}`));
client.login(BOT_TOKEN);
