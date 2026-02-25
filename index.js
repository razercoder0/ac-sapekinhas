const {
    Client, GatewayIntentBits, ActionRowBuilder, ButtonBuilder,
    ButtonStyle, EmbedBuilder, SlashCommandBuilder, REST, Routes,
    PermissionFlagsBits
} = require('discord.js');
const express  = require('express');
const crypto   = require('crypto');
const https    = require('https');
const mongoose = require('mongoose');

// ── CONFIG ────────────────────────────────────────────────────────────────────
const BOT_TOKEN     = process.env.BOT_TOKEN;
const CLIENT_ID     = process.env.CLIENT_ID;
const GUILD_ID      = process.env.GUILD_ID;
const CHANNEL_ID    = process.env.CHANNEL_ID;
const LOG_CHANNEL   = process.env.LOG_CHANNEL_ID;
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID;
const API_SECRET    = process.env.API_SECRET;
const MONGO_URI     = process.env.MONGO_URI;      // mongodb+srv://...
const PORT          = process.env.PORT || 3000;
const SELF_URL      = process.env.SELF_URL || null;
// ─────────────────────────────────────────────────────────────────────────────

// ── MONGOOSE SCHEMA ───────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
    username:    { type: String, required: true, unique: true },
    passwordHash:{ type: String, required: true },
    hwid:        { type: String, default: null },   // vinculado no primeiro login
    discordId:   { type: String, default: null },   // discord user id de quem foi registrado
    status:      { type: String, default: 'active', enum: ['active', 'banned'] },
    registeredBy:{ type: String },                  // admin que registrou
    registeredAt:{ type: Date, default: Date.now },
    lastLogin:   { type: Date, default: null },
    sessions:    { type: Number, default: 0 },
    history:     [{ action: String, by: String, at: Date, note: String }]
});

const User = mongoose.model('User', userSchema);

// ── HELPERS ───────────────────────────────────────────────────────────────────
const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });
const app    = express();

app.use(express.json({
    verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

function hashPassword(pass) {
    return crypto.createHmac('sha256', API_SECRET).update(pass).digest('hex');
}
function generatePassword(len = 12) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$';
    let pass = '';
    for (let i = 0; i < len; i++)
        pass += chars[Math.floor(Math.random() * chars.length)];
    return pass;
}
function generateToken(username, hwid) {
    return crypto.createHmac('sha256', API_SECRET)
        .update(username + hwid).digest('hex').substring(0, 32);
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
function now() { return new Date(); }
function fmtDate(date) {
    if (!date) return '—';
    return `<t:${Math.floor(new Date(date).getTime() / 1000)}:f>`;
}
async function sendLog(embed) {
    if (!LOG_CHANNEL) return;
    try { await (await client.channels.fetch(LOG_CHANNEL)).send({ embeds: [embed] }); } catch {}
}

// ── KEEP-ALIVE ────────────────────────────────────────────────────────────────
function startKeepAlive() {
    if (!SELF_URL) return;
    setInterval(() => {
        https.get(`https://${SELF_URL}/ping`, res => {
            console.log(`[keep-alive] ${res.statusCode}`);
        }).on('error', e => console.error('[keep-alive]', e.message));
    }, 10 * 60 * 1000);
    console.log(`✅ Keep-alive → https://${SELF_URL}/ping`);
}
app.get('/ping', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ── SLASH COMMANDS ────────────────────────────────────────────────────────────
const commands = [
    new SlashCommandBuilder()
        .setName('registrar')
        .setDescription('Registra um novo usuário e envia as credenciais por DM')
        .addUserOption(o => o.setName('usuario').setDescription('Usuário do Discord').setRequired(true))
        .addStringOption(o => o.setName('username').setDescription('Nome de login (deixe vazio pra usar o nick do Discord)').setRequired(false)),

    new SlashCommandBuilder()
        .setName('remover')
        .setDescription('Remove o registro de um usuário')
        .addStringOption(o => o.setName('username').setDescription('Username de login').setRequired(true))
        .addStringOption(o => o.setName('motivo').setDescription('Motivo').setRequired(false)),

    new SlashCommandBuilder()
        .setName('resetsenha')
        .setDescription('Gera uma nova senha e manda DM pro usuário')
        .addStringOption(o => o.setName('username').setDescription('Username de login').setRequired(true)),

    new SlashCommandBuilder()
        .setName('banir')
        .setDescription('Bane um usuário (impede login)')
        .addStringOption(o => o.setName('username').setDescription('Username de login').setRequired(true))
        .addStringOption(o => o.setName('motivo').setDescription('Motivo').setRequired(false)),

    new SlashCommandBuilder()
        .setName('desbanir')
        .setDescription('Remove o banimento de um usuário')
        .addStringOption(o => o.setName('username').setDescription('Username de login').setRequired(true))
        .addStringOption(o => o.setName('motivo').setDescription('Motivo').setRequired(false)),

    new SlashCommandBuilder()
        .setName('resetarhwid')
        .setDescription('Reseta o HWID vinculado (permite logar de outro PC)')
        .addStringOption(o => o.setName('username').setDescription('Username de login').setRequired(true)),

    new SlashCommandBuilder()
        .setName('info')
        .setDescription('Informações detalhadas de um usuário')
        .addStringOption(o => o.setName('username').setDescription('Username de login').setRequired(true)),

    new SlashCommandBuilder()
        .setName('lista')
        .setDescription('Lista todos os usuários')
        .addStringOption(o => o.setName('status').setDescription('Filtro').setRequired(false)
            .addChoices(
                { name: '✅ Ativos',   value: 'active' },
                { name: '🔴 Banidos', value: 'banned'  },
                { name: '📋 Todos',   value: 'all'     }
            )),

    new SlashCommandBuilder()
        .setName('online')
        .setDescription('Usuários com sessão ativa nos últimos 5 minutos'),

    new SlashCommandBuilder()
        .setName('stats')
        .setDescription('Estatísticas gerais do sistema'),

    new SlashCommandBuilder()
        .setName('historico')
        .setDescription('Histórico de ações de um usuário')
        .addStringOption(o => o.setName('username').setDescription('Username de login').setRequired(true)),
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
    if (!interaction.isChatInputCommand()) return;
    if (!isAdmin(interaction.member))
        return interaction.reply({ content: '❌ Sem permissão!', ephemeral: true });

    await interaction.deferReply({ ephemeral: false });

    const cmd      = interaction.commandName;
    const adminTag = interaction.user.username;

    // ── /registrar ────────────────────────────────────────────────────────────
    if (cmd === 'registrar') {
        const discordUser = interaction.options.getUser('usuario');
        let username      = interaction.options.getString('username') ||
                            discordUser.username.toLowerCase().replace(/[^a-z0-9_]/g, '');

        // Garante username único
        const exists = await User.findOne({ username });
        if (exists)
            return interaction.editReply(`❌ Username **${username}** já existe! Use outro ou passe um diferente.`);

        const password     = generatePassword();
        const passwordHash = hashPassword(password);

        const user = await User.create({
            username,
            passwordHash,
            discordId:    discordUser.id,
            registeredBy: adminTag,
            history: [{ action:'registered', by:adminTag, at:now(), note:'registro inicial' }]
        });

        // Manda DM pro usuário
        try {
            const dm = await discordUser.createDM();
            await dm.send({ embeds: [
                new EmbedBuilder()
                    .setTitle('🎮 Suas credenciais — Sapequinhas Client')
                    .setColor(0x8800ff)
                    .setDescription('Guarda essas informações! **Não compartilhe com ninguém.**')
                    .addFields(
                        { name: '👤 Usuário',  value: `\`${username}\``,  inline: true  },
                        { name: '🔑 Senha',    value: `\`${password}\``,  inline: true  },
                        { name: '📋 Instrução', value: 'Abra o injector, coloque seu usuário e senha e clique em Entrar.', inline: false }
                    )
                    .setFooter({ text: 'Sapequinhas Client • credenciais pessoais e intransferíveis' })
                    .setTimestamp()
            ]});
        } catch {
            await interaction.editReply(`⚠️ Não consegui mandar DM pra <@${discordUser.id}>. Verifique se as DMs estão abertas.\n\nCredenciais (manda no privado!):\n👤 \`${username}\`\n🔑 \`${password}\``);
            return;
        }

        await sendLog(new EmbedBuilder()
            .setTitle('📥 Novo Usuário Registrado').setColor(0x8800ff)
            .addFields(
                { name:'Username',   value:username,           inline:true },
                { name:'Discord',    value:`<@${discordUser.id}>`, inline:true },
                { name:'Admin',      value:adminTag,           inline:true }
            ).setTimestamp());

        return interaction.editReply({ embeds: [
            new EmbedBuilder().setTitle('✅ Usuário Registrado!').setColor(0x00cc44)
                .setDescription(`<@${discordUser.id}> foi registrado como \`${username}\` e recebeu as credenciais por DM.`)
                .setTimestamp()
        ]});
    }

    // ── /remover ──────────────────────────────────────────────────────────────
    if (cmd === 'remover') {
        const username = interaction.options.getString('username');
        const motivo   = interaction.options.getString('motivo') || '—';
        const user     = await User.findOne({ username });
        if (!user) return interaction.editReply(`❌ Usuário **${username}** não encontrado!`);

        await User.deleteOne({ username });
        await sendLog(new EmbedBuilder().setTitle('🗑️ Usuário Removido').setColor(0x888888)
            .addFields({ name:'Username', value:username, inline:true }, { name:'Admin', value:adminTag, inline:true }, { name:'Motivo', value:motivo }).setTimestamp());
        return interaction.editReply({ embeds: [
            new EmbedBuilder().setTitle('🗑️ Removido').setColor(0x888888)
                .setDescription(`**${username}** foi removido do sistema.\nMotivo: ${motivo}`)
        ]});
    }

    // ── /resetsenha ───────────────────────────────────────────────────────────
    if (cmd === 'resetsenha') {
        const username = interaction.options.getString('username');
        const user     = await User.findOne({ username });
        if (!user) return interaction.editReply(`❌ Usuário **${username}** não encontrado!`);

        const newPass = generatePassword();
        user.passwordHash = hashPassword(newPass);
        user.history.push({ action:'password_reset', by:adminTag, at:now(), note:'senha resetada pelo admin' });
        await user.save();

        // Tenta mandar DM
        let dmOk = false;
        if (user.discordId) {
            try {
                const discordUser = await client.users.fetch(user.discordId);
                const dm = await discordUser.createDM();
                await dm.send({ embeds: [
                    new EmbedBuilder()
                        .setTitle('🔑 Sua senha foi resetada — Sapequinhas Client')
                        .setColor(0xff6600)
                        .addFields(
                            { name:'👤 Usuário', value:`\`${username}\``, inline:true },
                            { name:'🔑 Nova Senha', value:`\`${newPass}\``, inline:true }
                        )
                        .setFooter({ text:'Não compartilhe com ninguém!' })
                        .setTimestamp()
                ]});
                dmOk = true;
            } catch {}
        }

        await sendLog(new EmbedBuilder().setTitle('🔑 Senha Resetada').setColor(0xff6600)
            .addFields({ name:'Username', value:username, inline:true }, { name:'Admin', value:adminTag, inline:true }).setTimestamp());

        return interaction.editReply({ embeds: [
            new EmbedBuilder().setTitle('🔑 Senha Resetada').setColor(0xff6600)
                .setDescription(dmOk
                    ? `Senha de **${username}** resetada e enviada por DM.`
                    : `Senha de **${username}** resetada.\n⚠️ Não consegui mandar DM. Nova senha: \`${newPass}\``)
        ]});
    }

    // ── /banir ────────────────────────────────────────────────────────────────
    if (cmd === 'banir') {
        const username = interaction.options.getString('username');
        const motivo   = interaction.options.getString('motivo') || '—';
        const user     = await User.findOne({ username });
        if (!user) return interaction.editReply(`❌ Usuário **${username}** não encontrado!`);
        if (user.status === 'banned') return interaction.editReply(`⚠️ **${username}** já está banido.`);

        user.status = 'banned';
        user.history.push({ action:'banned', by:adminTag, at:now(), note:motivo });
        await user.save();

        await sendLog(new EmbedBuilder().setTitle('🔨 Usuário Banido').setColor(0xcc2200)
            .addFields({ name:'Username', value:username, inline:true }, { name:'Admin', value:adminTag, inline:true }, { name:'Motivo', value:motivo }).setTimestamp());
        return interaction.editReply({ embeds: [
            new EmbedBuilder().setTitle('🔨 Banido').setColor(0xcc2200)
                .setDescription(`**${username}** foi banido.\nMotivo: ${motivo}`)
        ]});
    }

    // ── /desbanir ─────────────────────────────────────────────────────────────
    if (cmd === 'desbanir') {
        const username = interaction.options.getString('username');
        const motivo   = interaction.options.getString('motivo') || '—';
        const user     = await User.findOne({ username });
        if (!user) return interaction.editReply(`❌ Usuário **${username}** não encontrado!`);
        if (user.status === 'active') return interaction.editReply(`⚠️ **${username}** já está ativo.`);

        user.status = 'active';
        user.history.push({ action:'unbanned', by:adminTag, at:now(), note:motivo });
        await user.save();

        await sendLog(new EmbedBuilder().setTitle('✅ Usuário Desbanido').setColor(0x00cc44)
            .addFields({ name:'Username', value:username, inline:true }, { name:'Admin', value:adminTag, inline:true }, { name:'Motivo', value:motivo }).setTimestamp());
        return interaction.editReply({ embeds: [
            new EmbedBuilder().setTitle('✅ Desbanido').setColor(0x00cc44)
                .setDescription(`**${username}** foi desbanido.\nMotivo: ${motivo}`)
        ]});
    }

    // ── /resetarhwid ──────────────────────────────────────────────────────────
    if (cmd === 'resetarhwid') {
        const username = interaction.options.getString('username');
        const user     = await User.findOne({ username });
        if (!user) return interaction.editReply(`❌ Usuário **${username}** não encontrado!`);

        const oldHwid = user.hwid || '—';
        user.hwid = null;
        user.history.push({ action:'hwid_reset', by:adminTag, at:now(), note:`HWID anterior: ${oldHwid}` });
        await user.save();

        await sendLog(new EmbedBuilder().setTitle('🖥️ HWID Resetado').setColor(0x00aaff)
            .addFields({ name:'Username', value:username, inline:true }, { name:'Admin', value:adminTag, inline:true }, { name:'HWID anterior', value:`\`${oldHwid}\`` }).setTimestamp());
        return interaction.editReply({ embeds: [
            new EmbedBuilder().setTitle('🖥️ HWID Resetado').setColor(0x00aaff)
                .setDescription(`HWID de **${username}** resetado. Ele pode logar de outro PC agora.`)
        ]});
    }

    // ── /info ─────────────────────────────────────────────────────────────────
    if (cmd === 'info') {
        const username = interaction.options.getString('username');
        const user     = await User.findOne({ username });
        if (!user) return interaction.editReply(`❌ Usuário **${username}** não encontrado!`);

        return interaction.editReply({ embeds: [
            new EmbedBuilder()
                .setTitle(`👤 Info — ${user.username}`)
                .setColor(user.status === 'active' ? 0x00cc44 : 0xcc2200)
                .addFields(
                    { name:'Status',       value: user.status === 'active' ? '🟢 Ativo' : '🔴 Banido', inline:true },
                    { name:'Sessões',      value:`${user.sessions}`,                                    inline:true },
                    { name:'Último login', value:fmtDate(user.lastLogin),                               inline:true },
                    { name:'Discord',      value:user.discordId ? `<@${user.discordId}>` : '—',         inline:true },
                    { name:'Registrado por', value:user.registeredBy || '—',                            inline:true },
                    { name:'Registrado em', value:fmtDate(user.registeredAt),                           inline:true },
                    { name:'HWID',         value:user.hwid ? `\`${user.hwid}\`` : '*não vinculado*',    inline:false },
                ).setTimestamp()
        ]});
    }

    // ── /lista ────────────────────────────────────────────────────────────────
    if (cmd === 'lista') {
        const filter = interaction.options.getString('status') || 'all';
        const query  = filter === 'all' ? {} : { status: filter };
        const users  = await User.find(query).sort({ registeredAt: -1 });

        if (users.length === 0)
            return interaction.editReply(`Nenhum usuário com status **${filter}**.`);

        const lines = users.map(u =>
            `${u.status === 'active' ? '🟢' : '🔴'} **${u.username}** — ${fmtDate(u.registeredAt)}`
        );
        const chunks = [];
        let chunk = '';
        for (const l of lines) {
            if (chunk.length + l.length + 1 > 3800) { chunks.push(chunk); chunk = ''; }
            chunk += l + '\n';
        }
        if (chunk) chunks.push(chunk);

        await interaction.editReply({ embeds: [
            new EmbedBuilder()
                .setTitle(`📋 Lista — ${filter === 'all' ? 'Todos' : filter}`)
                .setColor(0x8800ff)
                .setDescription(chunks[0])
                .setFooter({ text:`Total: ${users.length}` })
                .setTimestamp()
        ]});
        for (let i = 1; i < chunks.length; i++)
            await interaction.followUp({ embeds: [new EmbedBuilder().setColor(0x8800ff).setDescription(chunks[i])] });
        return;
    }

    // ── /online ───────────────────────────────────────────────────────────────
    if (cmd === 'online') {
        const threshold = new Date(Date.now() - 5 * 60 * 1000);
        const active    = await User.find({ lastLogin: { $gte: threshold }, status:'active' });

        return interaction.editReply({ embeds: [
            new EmbedBuilder().setTitle('🟢 Online Agora').setColor(0x00cc44)
                .setDescription(active.length === 0 ? '*Ninguém online.*' :
                    active.map(u => `• **${u.username}** — visto ${fmtDate(u.lastLogin)} | Sessões: ${u.sessions}`).join('\n'))
                .setFooter({ text:`Total: ${active.length}` }).setTimestamp()
        ]});
    }

    // ── /stats ────────────────────────────────────────────────────────────────
    if (cmd === 'stats') {
        const total    = await User.countDocuments();
        const active   = await User.countDocuments({ status:'active' });
        const banned   = await User.countDocuments({ status:'banned' });
        const threshold = new Date(Date.now() - 5 * 60 * 1000);
        const online   = await User.countDocuments({ lastLogin: { $gte: threshold }, status:'active' });
        const sessions = await User.aggregate([{ $group: { _id:null, total: { $sum:'$sessions' } } }]);
        const totalSessions = sessions[0]?.total || 0;

        return interaction.editReply({ embeds: [
            new EmbedBuilder().setTitle('📊 Estatísticas').setColor(0x8800ff)
                .addFields(
                    { name:'🟢 Online agora',  value:`\`${online}\``,        inline:true },
                    { name:'✅ Ativos',         value:`\`${active}\``,        inline:true },
                    { name:'🔨 Banidos',        value:`\`${banned}\``,        inline:true },
                    { name:'👥 Total',          value:`\`${total}\``,         inline:true },
                    { name:'💉 Total sessões',  value:`\`${totalSessions}\``, inline:true },
                ).setTimestamp()
        ]});
    }

    // ── /historico ────────────────────────────────────────────────────────────
    if (cmd === 'historico') {
        const username = interaction.options.getString('username');
        const user     = await User.findOne({ username });
        if (!user) return interaction.editReply(`❌ Usuário **${username}** não encontrado!`);

        const emoji = { registered:'📥', banned:'🔨', unbanned:'✅', password_reset:'🔑', hwid_reset:'🖥️', login:'💉' };
        const lines = user.history.length === 0 ? ['*Sem histórico.*'] :
            user.history.slice(-25).map(h =>
                `${emoji[h.action] ?? '•'} **${h.action}** por \`${h.by}\` em ${fmtDate(h.at)}${h.note && h.note !== '—' ? `\n  ↳ ${h.note}` : ''}`
            );

        return interaction.editReply({ embeds: [
            new EmbedBuilder().setTitle(`📜 Histórico — ${user.username}`).setColor(0x8800ff)
                .setDescription(lines.join('\n'))
                .setFooter({ text:`Total: ${user.history.length} eventos` }).setTimestamp()
        ]});
    }
});

// ── API ROUTES ────────────────────────────────────────────────────────────────

// Injector chama isso com { username, password, hwid }
app.post('/login', async (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) return res.status(401).json({ error: 'Assinatura invalida' });

    const { username, password, hwid } = req.body;
    if (!username || !password || !hwid)
        return res.status(400).json({ error: 'Faltando username, password ou hwid' });

    const user = await User.findOne({ username });

    if (!user)                                    return res.json({ status: 'invalid', error: 'Usuario nao encontrado' });
    if (user.passwordHash !== hashPassword(password)) return res.json({ status: 'invalid', error: 'Senha incorreta' });
    if (user.status === 'banned')                 return res.json({ status: 'banned',  error: 'Conta banida' });

    // Vincula HWID na primeira vez
    if (!user.hwid) {
        user.hwid = hwid;
    } else if (user.hwid !== hwid) {
        // HWID diferente — bloqueado
        return res.json({ status: 'hwid_mismatch', error: 'HWID diferente do registrado. Contate um admin.' });
    }

    user.lastLogin = now();
    user.sessions  = (user.sessions || 0) + 1;
    user.history.push({ action:'login', by:username, at:now(), note:`HWID: ${hwid}` });
    await user.save();

    const token = generateToken(username, hwid);
    return res.json({ status: 'ok', token, username: user.username });
});

// Injector verifica se token ainda é válido (polling de 30s)
app.post('/verify', async (req, res) => {
    const sig = req.headers['x-signature'];
    if (!verifySignature(req, sig)) return res.status(401).json({ error: 'Assinatura invalida' });

    const { username, token, hwid } = req.body;
    const user = await User.findOne({ username });

    if (!user || user.status === 'banned')     return res.json({ valid: false, reason: 'banned' });
    if (user.hwid !== hwid)                    return res.json({ valid: false, reason: 'hwid_mismatch' });
    if (generateToken(username, hwid) !== token) return res.json({ valid: false, reason: 'invalid_token' });

    // Atualiza lastLogin
    user.lastLogin = now();
    await user.save();

    return res.json({ valid: true });
});

// ── START ─────────────────────────────────────────────────────────────────────
async function main() {
    // Conecta no MongoDB
    await mongoose.connect(MONGO_URI);
    console.log('✅ MongoDB conectado!');

    client.once('ready', async () => {
        console.log(`✅ Bot online: ${client.user.tag}`);
        await registerCommands();
        startKeepAlive();
    });

    app.listen(PORT, () => console.log(`✅ API na porta ${PORT}`));
    client.login(BOT_TOKEN);
}

main().catch(e => { console.error('❌ Erro fatal:', e); process.exit(1); });
