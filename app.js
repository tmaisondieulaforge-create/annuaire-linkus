/**
 * Application Annuaire Linkus - Version Sécurisée & Multi-utilisateurs
 * Gestion de l'authentification, gestion des collègues, contacts et Click-to-Call Linkus
 */

// État global de l'application
const state = {
    currentUser: null,
    contacts: [],
    companies: [],
    users: [],
    settings: {
        call_protocol: 'tel:',
        outbound_prefix: '',
        auto_format_fr: '1',
        theme: 'system'
    },
    activeFilter: 'all',
    selectedCompany: null,
    searchQuery: '',
    sortBy: 'last_name',
    viewMode: 'grid',
};

// =========================================================================
// INITIALISATION
// =========================================================================

document.addEventListener('DOMContentLoaded', async () => {
    initTheme();
    initEventListeners();
    await checkAuth();
});

// =========================================================================
// AUTHENTIFICATION (LOGIN, LOGOUT, SESSION)
// =========================================================================

async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me');
        if (res.ok) {
            const data = await res.json();
            if (data.authenticated && data.user) {
                onUserLoggedIn(data.user);
                return;
            }
        }
    } catch (err) {
        console.warn('Non authentifié ou serveur indisponible', err);
    }
    showLoginScreen();
}

function showLoginScreen() {
    state.currentUser = null;
    document.getElementById('loginContainer').classList.remove('hidden');
    document.getElementById('appContainer').classList.add('hidden');
    document.getElementById('loginUsername').focus();
}

async function onUserLoggedIn(user) {
    state.currentUser = user;
    
    // Mettre à jour l'interface utilisateur
    document.getElementById('loginContainer').classList.add('hidden');
    document.getElementById('appContainer').classList.remove('hidden');
    
    document.getElementById('currentUserName').textContent = user.display_name || user.username;
    
    const roleBadge = document.getElementById('currentUserRoleBadge');
    if (user.role === 'admin') {
        roleBadge.textContent = 'Admin';
        roleBadge.className = 'text-[10px] text-indigo-600 dark:text-indigo-400 font-semibold uppercase';
        document.getElementById('openUsersBtn').classList.remove('hidden');
    } else if (user.role === 'readonly') {
        roleBadge.textContent = 'Lecture';
        roleBadge.className = 'text-[10px] text-slate-500 dark:text-slate-400 font-semibold uppercase';
        document.getElementById('openUsersBtn').classList.add('hidden');
        document.getElementById('addContactBtn').classList.add('hidden');
    } else {
        roleBadge.textContent = 'Éditeur';
        roleBadge.className = 'text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold uppercase';
        document.getElementById('openUsersBtn').classList.add('hidden');
        document.getElementById('addContactBtn').classList.remove('hidden');
    }

    await loadSettings();
    await refreshData();
}

async function handleLoginSubmit(e) {
    e.preventDefault();
    const errorEl = document.getElementById('loginErrorMsg');
    const submitBtn = document.getElementById('loginSubmitBtn');
    
    errorEl.classList.add('hidden');
    submitBtn.disabled = true;
    submitBtn.classList.add('opacity-70');

    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (res.ok) {
            const data = await res.json();
            document.getElementById('loginForm').reset();
            onUserLoggedIn(data.user);
            showToast(`Bienvenue, ${data.user.display_name || data.user.username} !`, 'success');
        } else {
            const err = await res.json();
            errorEl.textContent = err.error || 'Identifiant ou mot de passe incorrect';
            errorEl.classList.remove('hidden');
        }
    } catch (err) {
        errorEl.textContent = 'Erreur de connexion au serveur';
        errorEl.classList.remove('hidden');
    } finally {
        submitBtn.disabled = false;
        submitBtn.classList.remove('opacity-70');
    }
}

async function handleLogout() {
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (err) {}
    showToast('Déconnexion effectuée', 'info');
    showLoginScreen();
}

// =========================================================================
// GESTION DES COLLÈGUES / UTILISATEURS (ADMINISTRATION)
// =========================================================================

async function openUsersModal() {
    if (!state.currentUser || state.currentUser.role !== 'admin') return;
    document.getElementById('usersModal').classList.remove('hidden');
    await loadUsersList();
}

async function loadUsersList() {
    try {
        const res = await fetch('/api/users');
        if (res.ok) {
            state.users = await res.json();
            renderUsersList();
        }
    } catch (err) {
        console.error('Erreur chargement utilisateurs', err);
    }
}

function renderUsersList() {
    const container = document.getElementById('usersListContainer');
    const countBadge = document.getElementById('usersCountBadge');
    countBadge.textContent = state.users.length;

    if (state.users.length === 0) {
        container.innerHTML = `<div class="p-4 text-xs text-slate-400 text-center">Aucun collègue enregistré</div>`;
        return;
    }

    container.innerHTML = state.users.map(u => {
        let roleLabel = 'Éditeur';
        let roleClass = 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300';
        if (u.role === 'admin') {
            roleLabel = 'Administrateur';
            roleClass = 'bg-indigo-100 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-300';
        } else if (u.role === 'readonly') {
            roleLabel = 'Lecture seule';
            roleClass = 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400';
        }

        const isMe = u.id === state.currentUser.id;

        return `
            <div class="p-3.5 flex items-center justify-between gap-3 text-xs">
                <div class="flex items-center gap-3 min-w-0">
                    <div class="w-8 h-8 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center font-bold text-slate-700 dark:text-slate-200 text-xs">
                        ${(u.display_name || u.username).charAt(0).toUpperCase()}
                    </div>
                    <div class="min-w-0">
                        <div class="font-bold text-slate-800 dark:text-slate-100 flex items-center gap-1.5">
                            <span class="truncate">${escapeHtml(u.display_name || u.username)}</span>
                            ${isMe ? '<span class="text-[10px] text-emerald-600 font-normal">(Vous)</span>' : ''}
                        </div>
                        <div class="text-[11px] text-slate-400 font-mono">@${escapeHtml(u.username)}</div>
                    </div>
                </div>

                <div class="flex items-center gap-2">
                    <span class="px-2 py-0.5 rounded-full text-[10px] font-semibold ${roleClass}">${roleLabel}</span>
                    <button onclick="handlePromptPasswordReset(${u.id}, '${escapeJs(u.display_name || u.username)}')" title="Modifier le mot de passe" class="p-1.5 text-slate-400 hover:text-indigo-600 rounded">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                    </button>
                    ${!isMe ? `
                        <button onclick="handleDeleteUser(${u.id}, '${escapeJs(u.display_name || u.username)}')" title="Supprimer ce collègue" class="p-1.5 text-slate-400 hover:text-rose-600 rounded">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                        </button>
                    ` : ''}
                </div>
            </div>
        `;
    }).join('');
}

async function handleAddUser(e) {
    e.preventDefault();
    const username = document.getElementById('newUsername').value.trim();
    const display_name = document.getElementById('newDisplayName').value.trim();
    const password = document.getElementById('newPassword').value;
    const role = document.getElementById('newRole').value;

    try {
        const res = await fetch('/api/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, display_name, password, role })
        });

        if (res.ok) {
            document.getElementById('addUserForm').reset();
            showToast(`Compte pour ${display_name || username} créé !`, 'success');
            await loadUsersList();
        } else {
            const err = await res.json();
            showToast(err.error || 'Erreur lors de la création', 'error');
        }
    } catch (err) {
        showToast('Erreur serveur', 'error');
    }
}

async function handleDeleteUser(userId, name) {
    if (!confirm(`Supprimer l'accès du collègue "${name}" ?`)) return;

    try {
        const res = await fetch(`/api/users/${userId}`, { method: 'DELETE' });
        if (res.ok) {
            showToast('Utilisateur supprimé', 'info');
            await loadUsersList();
        } else {
            const err = await res.json();
            showToast(err.error || 'Erreur lors de la suppression', 'error');
        }
    } catch (err) {
        showToast('Erreur serveur', 'error');
    }
}

async function handlePromptPasswordReset(userId, name) {
    const newPwd = prompt(`Nouveau mot de passe pour "${name}" :`);
    if (!newPwd || !newPwd.trim()) return;

    try {
        const res = await fetch(`/api/users/${userId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: newPwd.trim() })
        });

        if (res.ok) {
            showToast(`Mot de passe de ${name} mis à jour !`, 'success');
        } else {
            const err = await res.json();
            showToast(err.error || 'Erreur', 'error');
        }
    } catch (err) {
        showToast('Erreur de communication serveur', 'error');
    }
}

// =========================================================================
// GESTION DU THÈME (DARK / LIGHT / SYSTEM)
// =========================================================================

function initTheme() {
    const savedTheme = localStorage.getItem('theme_preference') || 'system';
    state.settings.theme = savedTheme;
    applyTheme(savedTheme, false);

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    mediaQuery.addEventListener('change', () => {
        if (state.settings.theme === 'system') {
            applyTheme('system', false);
        }
    });

    const toggleBtn = document.getElementById('themeToggleBtn');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const isCurrentlyDark = document.documentElement.classList.contains('dark');
            const newTheme = isCurrentlyDark ? 'light' : 'dark';
            setTheme(newTheme, true);
        });
    }

    const settingThemeSelect = document.getElementById('settingTheme');
    if (settingThemeSelect) {
        settingThemeSelect.value = savedTheme;
        settingThemeSelect.addEventListener('change', (e) => {
            setTheme(e.target.value, true);
        });
    }
}

function applyTheme(themeName, showToastNotify = false) {
    const isDark = themeName === 'dark' || (themeName === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    
    if (isDark) {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }

    const settingSelect = document.getElementById('settingTheme');
    if (settingSelect) {
        settingSelect.value = themeName;
    }

    if (showToastNotify) {
        let msg = 'Thème Clair activé';
        if (themeName === 'dark') msg = 'Thème Sombre activé';
        if (themeName === 'system') msg = 'Thème Automatique activé';
        showToast(msg, 'info');
    }
}

function setTheme(themeName, showToastNotify = false) {
    state.settings.theme = themeName;
    localStorage.setItem('theme_preference', themeName);
    applyTheme(themeName, showToastNotify);

    if (state.currentUser) {
        fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ theme: themeName })
        }).catch(() => {});
    }
}

// =========================================================================
// ÉCOUTEURS D'ÉVÉNEMENTS GÉNÉRAUX
// =========================================================================

function initEventListeners() {
    // Formulaire Login
    document.getElementById('loginForm').addEventListener('submit', handleLoginSubmit);
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);

    // Formulaire Ajout Collègue
    document.getElementById('addUserForm').addEventListener('submit', handleAddUser);

    // Recherche
    const searchInput = document.getElementById('searchInput');
    const clearSearchBtn = document.getElementById('clearSearchBtn');

    let debounceTimer;
    searchInput.addEventListener('input', (e) => {
        clearTimeout(debounceTimer);
        state.searchQuery = e.target.value.trim();
        clearSearchBtn.classList.toggle('hidden', state.searchQuery.length === 0);
        debounceTimer = setTimeout(() => renderContacts(), 150);
    });

    clearSearchBtn.addEventListener('click', () => {
        searchInput.value = '';
        state.searchQuery = '';
        clearSearchBtn.classList.add('hidden');
        renderContacts();
        searchInput.focus();
    });

    // Raccourcis clavier
    window.addEventListener('keydown', (e) => {
        if ((e.ctrlKey && e.key.toLowerCase() === 'k') || (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA')) {
            e.preventDefault();
            searchInput.focus();
            searchInput.select();
        }
        if (e.key === 'Escape') closeAllModals();
    });

    // Filtres
    document.getElementById('filterAllBtn').addEventListener('click', () => setFilter('all'));
    document.getElementById('filterFavBtn').addEventListener('click', () => setFilter('favorites'));
    document.getElementById('companyFilterInput').addEventListener('input', (e) => renderCompaniesList(e.target.value.trim().toLowerCase()));
    document.getElementById('resetFilterPill').addEventListener('click', () => setFilter('all'));

    // Tri & Mode vue
    document.getElementById('sortBySelect').addEventListener('change', (e) => {
        state.sortBy = e.target.value;
        loadContacts();
    });
    document.getElementById('viewGridBtn').addEventListener('click', () => setViewMode('grid'));
    document.getElementById('viewListBtn').addEventListener('click', () => setViewMode('list'));

    // Modals : Boutons d'ouverture
    document.getElementById('addContactBtn').addEventListener('click', () => openContactModal());
    document.getElementById('emptyStateAddBtn').addEventListener('click', () => openContactModal());
    document.getElementById('openDialpadBtn').addEventListener('click', () => openDialpadModal());
    document.getElementById('openSettingsBtn').addEventListener('click', () => openSettingsModal());
    document.getElementById('openImportExportBtn').addEventListener('click', () => openImportExportModal());
    document.getElementById('openUsersBtn').addEventListener('click', () => openUsersModal());

    // Modals : Boutons de fermeture
    document.getElementById('closeContactModalBtn').addEventListener('click', closeAllModals);
    document.getElementById('cancelContactModalBtn').addEventListener('click', closeAllModals);
    document.getElementById('closeDialpadModalBtn').addEventListener('click', closeAllModals);
    document.getElementById('closeSettingsModalBtn').addEventListener('click', closeAllModals);
    document.getElementById('closeImportExportModalBtn').addEventListener('click', closeAllModals);
    document.getElementById('closeUsersModalBtn').addEventListener('click', closeAllModals);

    // Clic extérieur pour fermer
    ['contactModal', 'dialpadModal', 'settingsModal', 'importExportModal', 'usersModal'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('click', (e) => {
                if (e.target.id === id) closeAllModals();
            });
        }
    });

    // Formulaire de contact
    document.getElementById('contactForm').addEventListener('submit', handleContactFormSubmit);
    document.getElementById('deleteContactBtn').addEventListener('click', handleDeleteContact);

    // Paramètres
    document.getElementById('saveSettingsBtn').addEventListener('click', handleSaveSettings);
    document.getElementById('testCallBtn').addEventListener('click', () => {
        const num = document.getElementById('testCallNumber').value.trim();
        if (num) makeCall(num);
    });

    // Dialpad
    initDialpad();

    // Import CSV
    const csvFileInput = document.getElementById('csvFileInput');
    document.getElementById('triggerCsvUploadBtn').addEventListener('click', () => csvFileInput.click());
    csvFileInput.addEventListener('change', handleCsvUpload);
}

// =========================================================================
// API & DONNÉES CONTACTS
// =========================================================================

async function refreshData() {
    await Promise.all([
        loadContacts(),
        loadCompanies(),
        loadStats()
    ]);
}

async function loadSettings() {
    try {
        const res = await fetch('/api/settings');
        if (res.ok) {
            const serverSettings = await res.json();
            state.settings = { ...state.settings, ...serverSettings };
            document.getElementById('settingProtocol').value = state.settings.call_protocol || 'tel:';
            document.getElementById('settingPrefix').value = state.settings.outbound_prefix || '';
            if (serverSettings.theme) {
                state.settings.theme = serverSettings.theme;
                localStorage.setItem('theme_preference', serverSettings.theme);
                applyTheme(serverSettings.theme, false);
            }
        }
    } catch (err) {
        console.warn('Impossible de charger les réglages', err);
    }
}

async function loadStats() {
    try {
        const res = await fetch('/api/stats');
        if (res.ok) {
            const stats = await res.json();
            document.getElementById('badgeTotalCount').textContent = stats.total_contacts;
            document.getElementById('badgeFavCount').textContent = stats.total_favorites;
            document.getElementById('companiesCount').textContent = stats.total_companies;
        }
    } catch (err) {}
}

async function loadCompanies() {
    try {
        const res = await fetch('/api/companies');
        if (res.ok) {
            state.companies = await res.json();
            renderCompaniesList();
            updateCompanyDatalist();
        }
    } catch (err) {}
}

function updateCompanyDatalist() {
    const datalist = document.getElementById('companiesDatalist');
    datalist.innerHTML = state.companies.map(c => `<option value="${escapeHtml(c.company)}">`).join('');
}

async function loadContacts() {
    try {
        let url = `/api/contacts?sort=${state.sortBy}`;
        if (state.activeFilter === 'favorites') {
            url += '&favorite=1';
        } else if (state.activeFilter.startsWith('company:')) {
            const companyName = state.activeFilter.replace('company:', '');
            url += `&company=${encodeURIComponent(companyName)}`;
        }

        const res = await fetch(url);
        if (res.ok) {
            state.contacts = await res.json();
            renderContacts();
        } else if (res.status === 401) {
            showLoginScreen();
        }
    } catch (err) {
        console.error('Erreur chargement contacts', err);
    }
}

// =========================================================================
// RENDU DE L'INTERFACE
// =========================================================================

function setFilter(filterType, companyName = null) {
    state.activeFilter = companyName ? `company:${companyName}` : filterType;
    state.selectedCompany = companyName;

    document.querySelectorAll('.filter-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.company-badge-btn').forEach(btn => btn.classList.remove('active'));

    const resetPill = document.getElementById('resetFilterPill');
    const viewLabel = document.getElementById('currentViewLabel');

    if (filterType === 'all') {
        document.getElementById('filterAllBtn').classList.add('active');
        viewLabel.textContent = 'Tous les contacts';
        resetPill.classList.add('hidden');
    } else if (filterType === 'favorites') {
        document.getElementById('filterFavBtn').classList.add('active');
        viewLabel.textContent = '⭐ Contacts Favoris';
        resetPill.classList.remove('hidden');
    } else if (companyName) {
        const activeCompBtn = document.querySelector(`[data-company="${escapeHtml(companyName)}"]`);
        if (activeCompBtn) activeCompBtn.classList.add('active');
        viewLabel.textContent = `Société : ${companyName}`;
        resetPill.classList.remove('hidden');
    }

    loadContacts();
}

function setViewMode(mode) {
    state.viewMode = mode;
    const gridBtn = document.getElementById('viewGridBtn');
    const listBtn = document.getElementById('viewListBtn');

    if (mode === 'grid') {
        gridBtn.className = 'p-1 rounded text-emerald-700 dark:text-emerald-400 bg-white dark:bg-slate-700 shadow-sm';
        listBtn.className = 'p-1 rounded text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200';
    } else {
        listBtn.className = 'p-1 rounded text-emerald-700 dark:text-emerald-400 bg-white dark:bg-slate-700 shadow-sm';
        gridBtn.className = 'p-1 rounded text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200';
    }
    renderContacts();
}

function renderCompaniesList(filterTerm = '') {
    const container = document.getElementById('companiesList');
    const filtered = state.companies.filter(c => 
        !filterTerm || c.company.toLowerCase().includes(filterTerm)
    );

    if (filtered.length === 0) {
        container.innerHTML = `<div class="text-xs text-slate-400 dark:text-slate-500 py-3 text-center">Aucune société</div>`;
        return;
    }

    container.innerHTML = filtered.map(c => {
        const isSelected = state.activeFilter === `company:${c.company}`;
        return `
            <button class="company-badge-btn w-full text-left px-2.5 py-1.5 rounded-xl text-xs font-medium flex items-center justify-between transition-colors ${isSelected ? 'active bg-emerald-600 text-white font-semibold' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'}"
                data-company="${escapeHtml(c.company)}"
                onclick="setFilter('company', '${escapeJs(c.company)}')">
                <span class="truncate pr-2">${escapeHtml(c.company)}</span>
                <span class="count text-[10px] ${isSelected ? 'bg-emerald-700 text-white' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'} px-2 py-0.5 rounded-full font-bold">${c.count}</span>
            </button>
        `;
    }).join('');
}

function renderContacts() {
    const container = document.getElementById('contactsContainer');
    const emptyState = document.getElementById('emptyState');
    const resultsCountBadge = document.getElementById('resultsCountBadge');

    let list = state.contacts;

    if (state.searchQuery) {
        const q = state.searchQuery.toLowerCase();
        list = list.filter(c => {
            return (
                (c.last_name && c.last_name.toLowerCase().includes(q)) ||
                (c.first_name && c.first_name.toLowerCase().includes(q)) ||
                (c.company && c.company.toLowerCase().includes(q)) ||
                (c.job_title && c.job_title.toLowerCase().includes(q)) ||
                (c.phone_mobile && c.phone_mobile.replace(/\s+/g, '').includes(q.replace(/\s+/g, ''))) ||
                (c.phone_direct && c.phone_direct.replace(/\s+/g, '').includes(q.replace(/\s+/g, ''))) ||
                (c.phone_company && c.phone_company.replace(/\s+/g, '').includes(q.replace(/\s+/g, ''))) ||
                (c.email && c.email.toLowerCase().includes(q)) ||
                (c.notes && c.notes.toLowerCase().includes(q))
            );
        });
    }

    resultsCountBadge.textContent = `${list.length} contact${list.length > 1 ? 's' : ''}`;

    if (list.length === 0) {
        container.innerHTML = '';
        emptyState.classList.remove('hidden');
        return;
    }

    emptyState.classList.add('hidden');

    if (state.viewMode === 'grid') {
        container.className = 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pb-12';
        container.innerHTML = list.map(c => renderContactCard(c)).join('');
    } else {
        container.className = 'bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm pb-2 transition-colors';
        container.innerHTML = renderContactTable(list);
    }
}

// =========================================================================
// COMPOSANTS DE CONTACT (CARTE & TABLEAU)
// =========================================================================

function getAvatarColor(name) {
    const colors = [
        'bg-blue-500 text-white',
        'bg-emerald-600 text-white',
        'bg-indigo-500 text-white',
        'bg-violet-600 text-white',
        'bg-amber-600 text-white',
        'bg-teal-600 text-white',
        'bg-rose-500 text-white',
    ];
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
        hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }
    return colors[Math.abs(hash) % colors.length];
}

function getInitials(lastName, firstName) {
    const l = lastName ? lastName.charAt(0).toUpperCase() : '';
    const f = firstName ? firstName.charAt(0).toUpperCase() : '';
    return `${f}${l}` || '?';
}

function renderContactCard(c) {
    const fullName = `${c.first_name || ''} ${c.last_name || ''}`.trim();
    const initials = getInitials(c.last_name, c.first_name);
    const avatarColor = getAvatarColor(fullName);
    const canEdit = state.currentUser && state.currentUser.role !== 'readonly';

    return `
        <div class="contact-card bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/90 dark:border-slate-800 p-4 shadow-sm flex flex-col justify-between transition-colors">
            <div>
                <!-- En-tête : Avatar + Nom + Favori -->
                <div class="flex items-start justify-between gap-3 mb-3">
                    <div class="flex items-center gap-3 min-w-0">
                        <div class="w-11 h-11 rounded-xl ${avatarColor} flex items-center justify-center font-bold text-sm flex-shrink-0 shadow-sm">
                            ${initials}
                        </div>
                        <div class="min-w-0">
                            <h4 class="font-bold text-slate-900 dark:text-slate-100 text-sm truncate leading-snug ${canEdit ? 'hover:text-emerald-700 dark:hover:text-emerald-400 cursor-pointer' : ''}" 
                                ${canEdit ? `onclick="openContactModal(${c.id})"` : ''}>
                                ${escapeHtml(c.last_name.toUpperCase())} ${escapeHtml(c.first_name || '')}
                            </h4>
                            ${c.job_title ? `<p class="text-[11px] text-slate-500 dark:text-slate-400 truncate">${escapeHtml(c.job_title)}</p>` : ''}
                            ${c.company ? `
                                <button onclick="setFilter('company', '${escapeJs(c.company)}')" class="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 hover:bg-emerald-100 dark:hover:bg-emerald-900/60 px-2 py-0.5 rounded-md mt-0.5 transition-colors">
                                    🏢 ${escapeHtml(c.company)}
                                </button>
                            ` : ''}
                        </div>
                    </div>

                    <!-- Favori & Menu -->
                    <div class="flex items-center gap-1">
                        <button onclick="toggleFavorite(${c.id})" title="${c.is_favorite ? 'Retirer des favoris' : 'Ajouter aux favoris'}" class="p-1.5 text-slate-300 dark:text-slate-600 hover:text-amber-500 transition-colors">
                            <svg class="w-5 h-5 ${c.is_favorite ? 'text-amber-400 fill-amber-400' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                            </svg>
                        </button>
                        ${canEdit ? `
                            <button onclick="openContactModal(${c.id})" title="Modifier" class="p-1.5 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                                </svg>
                            </button>
                        ` : ''}
                    </div>
                </div>

                <!-- Lignes Téléphoniques avec Click-to-Call -->
                <div class="space-y-1.5 mb-3 bg-slate-50/70 dark:bg-slate-850/80 p-2.5 rounded-xl border border-slate-100 dark:border-slate-800 transition-colors">
                    ${c.phone_mobile ? renderPhoneBadge('Mobile', c.phone_mobile, '📱') : ''}
                    ${c.phone_direct ? renderPhoneBadge('Direct', c.phone_direct, '📞') : ''}
                    ${c.phone_company ? renderPhoneBadge('Standard', c.phone_company, '🏢') : ''}
                    ${!c.phone_mobile && !c.phone_direct && !c.phone_company ? `
                        <div class="text-[11px] text-slate-400 dark:text-slate-500 italic py-1 text-center">Aucun numéro enregistré</div>
                    ` : ''}
                </div>

                <!-- Email & Notes -->
                ${c.email ? `
                    <div class="flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300 mb-1.5 truncate">
                        <svg class="w-3.5 h-3.5 text-slate-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                        </svg>
                        <a href="mailto:${escapeHtml(c.email)}" class="hover:text-emerald-700 dark:hover:text-emerald-400 hover:underline truncate">${escapeHtml(c.email)}</a>
                    </div>
                ` : ''}

                ${c.notes ? `
                    <div class="text-[11px] text-slate-600 dark:text-slate-300 bg-amber-50/60 dark:bg-amber-950/30 border border-amber-100 dark:border-amber-900/40 rounded-lg p-2 mt-2 leading-relaxed">
                        <span class="font-semibold text-amber-900 dark:text-amber-400">Note :</span> ${escapeHtml(c.notes)}
                    </div>
                ` : ''}
            </div>

            <!-- Bouton appel prioritaire en bas de carte -->
            ${(c.phone_mobile || c.phone_direct || c.phone_company) ? `
                <div class="pt-3 mt-3 border-t border-slate-100 dark:border-slate-800">
                    <button onclick="makeCall('${escapeJs(c.phone_mobile || c.phone_direct || c.phone_company)}', '${escapeJs(fullName)}')" 
                        class="call-btn w-full py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs font-semibold flex items-center justify-center gap-2 shadow-sm shadow-emerald-600/20 active:scale-98">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                        </svg>
                        <span>Appeler avec Linkus</span>
                        <span class="opacity-80 font-normal">(${escapeHtml(c.phone_mobile || c.phone_direct || c.phone_company)})</span>
                    </button>
                </div>
            ` : ''}
        </div>
    `;
}

function renderPhoneBadge(type, number, icon) {
    return `
        <div class="flex items-center justify-between gap-1 text-xs py-0.5">
            <span class="text-slate-500 dark:text-slate-400 font-medium flex items-center gap-1">
                <span>${icon}</span>
                <span class="text-[10px] text-slate-400 dark:text-slate-500 uppercase tracking-wide">${type}</span>
            </span>
            <div class="flex items-center gap-1.5 font-mono text-xs font-semibold text-slate-800 dark:text-slate-200">
                <button onclick="makeCall('${escapeJs(number)}')" title="Appeler ce numéro avec Linkus" class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">
                    ${escapeHtml(number)}
                </button>
                <button onclick="copyToClipboard('${escapeJs(number)}')" title="Copier le numéro" class="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                </button>
                <button onclick="makeCall('${escapeJs(number)}')" title="Appeler avec Linkus" class="p-1 bg-emerald-100 hover:bg-emerald-200 dark:bg-emerald-950 dark:hover:bg-emerald-900 text-emerald-800 dark:text-emerald-300 rounded-lg transition-colors">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                    </svg>
                </button>
            </div>
        </div>
    `;
}

function renderContactTable(contacts) {
    const canEdit = state.currentUser && state.currentUser.role !== 'readonly';
    return `
        <div class="overflow-x-auto">
            <table class="w-full text-left text-xs">
                <thead class="bg-slate-50 dark:bg-slate-850 border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-semibold uppercase text-[10px]">
                    <tr>
                        <th class="py-3 px-4 w-10"></th>
                        <th class="py-3 px-4">Nom / Prénom</th>
                        <th class="py-3 px-4">Société</th>
                        <th class="py-3 px-4">Mobile</th>
                        <th class="py-3 px-4">Fixe / Direct</th>
                        <th class="py-3 px-4">Email</th>
                        <th class="py-3 px-4 text-center">Appel Linkus</th>
                        <th class="py-3 px-4 text-right">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 dark:divide-slate-800">
                    ${contacts.map(c => {
                        const fullName = `${c.last_name.toUpperCase()} ${c.first_name || ''}`.trim();
                        const priorityNumber = c.phone_mobile || c.phone_direct || c.phone_company;
                        return `
                            <tr class="hover:bg-slate-50/80 dark:hover:bg-slate-850/60 transition-colors">
                                <td class="py-2.5 px-4">
                                    <button onclick="toggleFavorite(${c.id})" class="text-slate-300 dark:text-slate-600 hover:text-amber-500">
                                        <svg class="w-4 h-4 ${c.is_favorite ? 'text-amber-400 fill-amber-400' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                                        </svg>
                                    </button>
                                </td>
                                <td class="py-2.5 px-4 font-semibold text-slate-800 dark:text-slate-100">
                                    <div class="${canEdit ? 'hover:text-emerald-700 dark:hover:text-emerald-400 cursor-pointer' : ''}" 
                                         ${canEdit ? `onclick="openContactModal(${c.id})"` : ''}>${escapeHtml(fullName)}</div>
                                    ${c.job_title ? `<div class="text-[10px] text-slate-400 dark:text-slate-500 font-normal">${escapeHtml(c.job_title)}</div>` : ''}
                                </td>
                                <td class="py-2.5 px-4">
                                    ${c.company ? `
                                        <button onclick="setFilter('company', '${escapeJs(c.company)}')" class="inline-flex items-center text-[11px] font-medium text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 px-2 py-0.5 rounded hover:bg-emerald-100 dark:hover:bg-emerald-900/60">
                                            ${escapeHtml(c.company)}
                                        </button>
                                    ` : '<span class="text-slate-300 dark:text-slate-600">-</span>'}
                                </td>
                                <td class="py-2.5 px-4 font-mono font-medium text-slate-700 dark:text-slate-200">
                                    ${c.phone_mobile ? `
                                        <button onclick="makeCall('${escapeJs(c.phone_mobile)}')" class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">
                                            ${escapeHtml(c.phone_mobile)}
                                        </button>
                                    ` : '<span class="text-slate-300 dark:text-slate-600">-</span>'}
                                </td>
                                <td class="py-2.5 px-4 font-mono font-medium text-slate-700 dark:text-slate-200">
                                    ${c.phone_direct ? `
                                        <button onclick="makeCall('${escapeJs(c.phone_direct)}')" class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">
                                            ${escapeHtml(c.phone_direct)}
                                        </button>
                                    ` : '<span class="text-slate-300 dark:text-slate-600">-</span>'}
                                </td>
                                <td class="py-2.5 px-4 text-slate-600 dark:text-slate-300">
                                    ${c.email ? `<a href="mailto:${escapeHtml(c.email)}" class="hover:text-emerald-700 dark:hover:text-emerald-400 hover:underline">${escapeHtml(c.email)}</a>` : '<span class="text-slate-300 dark:text-slate-600">-</span>'}
                                </td>
                                <td class="py-2.5 px-4 text-center">
                                    ${priorityNumber ? `
                                        <button onclick="makeCall('${escapeJs(priorityNumber)}', '${escapeJs(fullName)}')" class="inline-flex items-center gap-1 px-3 py-1 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-semibold shadow-sm transition-transform active:scale-95">
                                            <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                                            </svg>
                                            <span>Appeler</span>
                                        </button>
                                    ` : '<span class="text-slate-300 dark:text-slate-600 text-[11px]">Pas de tél</span>'}
                                </td>
                                <td class="py-2.5 px-4 text-right">
                                    ${canEdit ? `
                                        <button onclick="openContactModal(${c.id})" class="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200">
                                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                                            </svg>
                                        </button>
                                    ` : '<span class="text-slate-300 dark:text-slate-600">-</span>'}
                                </td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// =========================================================================
// MOTEUR CLICK-TO-CALL (LINKUS)
// =========================================================================

function cleanPhoneNumber(rawNumber) {
    if (!rawNumber) return '';
    let cleaned = rawNumber.replace(/[^\d+]/g, '');
    const prefix = state.settings.outbound_prefix || '';
    if (prefix) cleaned = prefix + cleaned;
    return cleaned;
}

function makeCall(rawNumber, contactName = '') {
    const formatted = cleanPhoneNumber(rawNumber);
    if (!formatted) {
        showToast('Numéro invalide', 'error');
        return;
    }

    const protocol = state.settings.call_protocol || 'tel:';
    let callUrl = (protocol === 'linkus:') ? `linkus:${formatted}` : `${protocol}${formatted}`;

    window.location.href = callUrl;
    const label = contactName ? `${contactName} (${formatted})` : formatted;
    showToast(`Appel vers ${label} lancé dans Linkus !`, 'success');
}

// =========================================================================
// GESTION DES CONTACTS
// =========================================================================

function openContactModal(contactId = null) {
    if (state.currentUser && state.currentUser.role === 'readonly') {
        showToast('Votre compte est en lecture seule', 'error');
        return;
    }

    const modal = document.getElementById('contactModal');
    const form = document.getElementById('contactForm');
    form.reset();

    const titleEl = document.getElementById('modalTitle');
    const deleteBtn = document.getElementById('deleteContactBtn');
    document.getElementById('contactId').value = contactId || '';

    if (contactId) {
        const contact = state.contacts.find(c => c.id === contactId);
        if (!contact) return;

        titleEl.textContent = 'Modifier le contact';
        deleteBtn.classList.remove('hidden');

        document.getElementById('lastNameInput').value = contact.last_name || '';
        document.getElementById('firstNameInput').value = contact.first_name || '';
        document.getElementById('companyInput').value = contact.company || '';
        document.getElementById('jobTitleInput').value = contact.job_title || '';
        document.getElementById('phoneMobileInput').value = contact.phone_mobile || '';
        document.getElementById('phoneDirectInput').value = contact.phone_direct || '';
        document.getElementById('phoneCompanyInput').value = contact.phone_company || '';
        document.getElementById('emailInput').value = contact.email || '';
        document.getElementById('notesInput').value = contact.notes || '';
        document.getElementById('isFavoriteInput').checked = !!contact.is_favorite;
    } else {
        titleEl.textContent = 'Nouveau contact';
        deleteBtn.classList.add('hidden');
        if (state.selectedCompany) {
            document.getElementById('companyInput').value = state.selectedCompany;
        }
    }

    modal.classList.remove('hidden');
    setTimeout(() => document.getElementById('lastNameInput').focus(), 50);
}

async function handleContactFormSubmit(e) {
    e.preventDefault();
    const contactId = document.getElementById('contactId').value;

    const payload = {
        last_name: document.getElementById('lastNameInput').value.trim(),
        first_name: document.getElementById('firstNameInput').value.trim(),
        company: document.getElementById('companyInput').value.trim(),
        job_title: document.getElementById('jobTitleInput').value.trim(),
        phone_mobile: document.getElementById('phoneMobileInput').value.trim(),
        phone_direct: document.getElementById('phoneDirectInput').value.trim(),
        phone_company: document.getElementById('phoneCompanyInput').value.trim(),
        email: document.getElementById('emailInput').value.trim(),
        notes: document.getElementById('notesInput').value.trim(),
        is_favorite: document.getElementById('isFavoriteInput').checked ? 1 : 0
    };

    try {
        let res;
        if (contactId) {
            res = await fetch(`/api/contacts/${contactId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } else {
            res = await fetch('/api/contacts', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        }

        if (res.ok) {
            closeAllModals();
            showToast(contactId ? 'Contact mis à jour' : 'Contact ajouté avec succès', 'success');
            await refreshData();
        } else {
            const err = await res.json();
            showToast(err.error || 'Erreur lors de l\'enregistrement', 'error');
        }
    } catch (err) {
        showToast('Erreur serveur', 'error');
    }
}

async function handleDeleteContact() {
    const contactId = document.getElementById('contactId').value;
    if (!contactId) return;

    if (!confirm('Supprimer définitivement ce contact ?')) return;

    try {
        const res = await fetch(`/api/contacts/${contactId}`, { method: 'DELETE' });
        if (res.ok) {
            closeAllModals();
            showToast('Contact supprimé', 'info');
            await refreshData();
        }
    } catch (err) {
        showToast('Erreur lors de la suppression', 'error');
    }
}

async function toggleFavorite(contactId) {
    try {
        const res = await fetch(`/api/contacts/${contactId}/toggle-favorite`, { method: 'POST' });
        if (res.ok) {
            const data = await res.json();
            const contact = state.contacts.find(c => c.id === contactId);
            if (contact) contact.is_favorite = data.is_favorite;
            renderContacts();
            loadStats();
        }
    } catch (err) {}
}

// =========================================================================
// CLAVIER VIRTUEL D'APPEL (DIALPAD)
// =========================================================================

function initDialpad() {
    const input = document.getElementById('dialpadInput');
    
    document.querySelectorAll('.dial-key').forEach(btn => {
        btn.addEventListener('click', () => {
            input.value += btn.dataset.key;
        });
    });

    document.getElementById('dialpadBackspaceBtn').addEventListener('click', () => {
        input.value = input.value.slice(0, -1);
    });

    document.getElementById('dialpadCallBtn').addEventListener('click', () => {
        const num = input.value.trim();
        if (num) {
            makeCall(num);
            closeAllModals();
        }
    });

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            document.getElementById('dialpadCallBtn').click();
        }
    });
}

function openDialpadModal() {
    const modal = document.getElementById('dialpadModal');
    const input = document.getElementById('dialpadInput');
    input.value = '';
    modal.classList.remove('hidden');
    setTimeout(() => input.focus(), 50);
}

// =========================================================================
// PARAMÈTRES LINKUS & IMPORT/EXPORT
// =========================================================================

function openSettingsModal() {
    document.getElementById('settingTheme').value = state.settings.theme || 'system';
    document.getElementById('settingsModal').classList.remove('hidden');
}

function openImportExportModal() {
    document.getElementById('importStatus').classList.add('hidden');
    document.getElementById('importExportModal').classList.remove('hidden');
}

async function handleSaveSettings() {
    const chosenTheme = document.getElementById('settingTheme').value;
    const payload = {
        call_protocol: document.getElementById('settingProtocol').value,
        outbound_prefix: document.getElementById('settingPrefix').value.trim(),
        theme: chosenTheme
    };

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            state.settings = { ...state.settings, ...payload };
            setTheme(chosenTheme, false);
            closeAllModals();
            showToast('Paramètres enregistrés !', 'success');
        }
    } catch (err) {
        showToast('Erreur de sauvegarde', 'error');
    }
}

async function handleCsvUpload(e) {
    if (state.currentUser && state.currentUser.role === 'readonly') {
        showToast('Import non autorisé en lecture seule', 'error');
        return;
    }

    const file = e.target.files[0];
    if (!file) return;

    const statusEl = document.getElementById('importStatus');
    statusEl.textContent = 'Importation en cours...';
    statusEl.className = 'text-xs font-medium mt-3 text-slate-500 dark:text-slate-400';
    statusEl.classList.remove('hidden');

    try {
        const text = await file.text();
        const res = await fetch('/api/import-csv', {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            body: text
        });

        if (res.ok) {
            const data = await res.json();
            statusEl.textContent = `Succès : ${data.count} contacts importés !`;
            statusEl.className = 'text-xs font-semibold mt-3 text-emerald-600 dark:text-emerald-400';
            showToast(`${data.count} contacts importés avec succès`, 'success');
            await refreshData();
        } else {
            const err = await res.json();
            statusEl.textContent = `Erreur : ${err.error || 'Fichier non valide'}`;
            statusEl.className = 'text-xs font-semibold mt-3 text-rose-600 dark:text-rose-400';
        }
    } catch (err) {
        statusEl.textContent = 'Erreur lors de la lecture du fichier';
        statusEl.className = 'text-xs font-semibold mt-3 text-rose-600 dark:text-rose-400';
    }
    e.target.value = '';
}

// =========================================================================
// UTILITAIRES
// =========================================================================

function closeAllModals() {
    ['contactModal', 'dialpadModal', 'settingsModal', 'importExportModal', 'usersModal'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add('hidden');
    });
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toastNotification');
    const msgEl = document.getElementById('toastMessage');
    const iconEl = document.getElementById('toastIcon');

    msgEl.textContent = message;

    if (type === 'success') {
        iconEl.innerHTML = `<svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
    } else if (type === 'error') {
        iconEl.innerHTML = `<svg class="w-4 h-4 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>`;
    } else {
        iconEl.innerHTML = `<svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
    }

    toast.classList.remove('translate-y-20', 'opacity-0');
    toast.classList.add('translate-y-0', 'opacity-100');

    setTimeout(() => {
        toast.classList.add('translate-y-20', 'opacity-0');
        toast.classList.remove('translate-y-0', 'opacity-100');
    }, 3200);
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(`Numéro ${text} copié !`, 'info');
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeJs(str) {
    if (!str) return '';
    return String(str).replace(/'/g, "\\'").replace(/"/g, '\\"');
}
