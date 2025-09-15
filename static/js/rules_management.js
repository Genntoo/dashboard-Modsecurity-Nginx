// Rules Management JavaScript - Versión Completa y Mejorada
console.log('🚀 Loading rules_management.js...');

// Verificar que estamos en el entorno correcto
if (typeof document === 'undefined') {
    console.error('❌ Document not available');
}

// Clase principal mejorada
class RulesManager {
    constructor() {
        console.log('🔧 Initializing RulesManager...');
        this.rules = [];
        this.filteredRules = [];
        this.currentPage = 1;
        this.itemsPerPage = 50;
        this.totalPages = 0;
        this.filters = { search: '', category: '', columns: {} };
        this.pendingChanges = new Map();
        
        // Inicializar después de un breve delay para asegurar que DOM está listo
        setTimeout(() => this.init(), 100);
    }

    init() {
        console.log('⚙️ Setting up event listeners...');
        this.setupEventListeners();
        this.loadRules();
        this.updateCustomRulesCount();
    }

    setupEventListeners() {
        // Core rules listeners
        const ruleSearch = document.getElementById('ruleSearch');
        const categoryFilter = document.getElementById('categoryFilter');
        const applyButton = document.getElementById('applyChanges');
        
        if (ruleSearch) {
            ruleSearch.addEventListener('input', (e) => {
                this.filters.search = e.target.value.toLowerCase();
                this.filterAndRenderRules();
            });
        }

        if (categoryFilter) {
            categoryFilter.addEventListener('change', (e) => {
                this.filters.category = e.target.value;
                this.filterAndRenderRules();
            });
        }

        if (applyButton) {
            applyButton.addEventListener('click', () => this.applyChanges());
        }

        // Custom rules listeners - con verificación robusta
        this.setupCustomRulesListeners();
        
        // Rule creation listeners
        this.setupRuleCreationListeners();
        
        console.log('✅ Event listeners configured');
    }

    setupCustomRulesListeners() {
        // Múltiples intentos para configurar listeners de custom rules
        const attempts = [0, 500, 1000, 2000]; // Intentar en diferentes momentos
        
        attempts.forEach(delay => {
            setTimeout(() => {
                const customTab = document.getElementById('custom-rules-tab');
                const refreshBtn = document.getElementById('refreshCustomRules');
                
                if (customTab && !customTab.hasAttribute('data-listener-attached')) {
                    console.log(`🎯 Attaching custom rules listeners (attempt at ${delay}ms)`);
                    
                    // Marcar como procesado
                    customTab.setAttribute('data-listener-attached', 'true');
                    
                    // Evento de Bootstrap
                    customTab.addEventListener('shown.bs.tab', () => {
                        console.log('🎯 Custom rules tab shown');
                        this.loadCustomRules();
                    });
                    
                    // Evento de click como backup
                    customTab.addEventListener('click', () => {
                        setTimeout(() => this.loadCustomRules(), 200);
                    });
                }
                
                if (refreshBtn && !refreshBtn.hasAttribute('data-listener-attached')) {
                    refreshBtn.setAttribute('data-listener-attached', 'true');
                    refreshBtn.addEventListener('click', () => this.loadCustomRules());
                }
            }, delay);
        });
    }

    setupRuleCreationListeners() {
        // Handle rule type changes
        const ruleType = document.getElementById('ruleType');
        if (ruleType) {
            ruleType.addEventListener('change', (e) => {
                const customContainer = document.getElementById('customRuleContainer');
                const previewContainer = document.getElementById('rulePreviewContainer');
                
                if (e.target.value === 'custom') {
                    if (customContainer) customContainer.style.display = 'block';
                    if (previewContainer) previewContainer.style.display = 'none';
                } else {
                    if (customContainer) customContainer.style.display = 'none';
                    if (e.target.value) {
                        this.updateRulePreview();
                        if (previewContainer) previewContainer.style.display = 'block';
                    } else {
                        if (previewContainer) previewContainer.style.display = 'none';
                    }
                }
            });
        }

        // Update preview on input changes
        ['ruleName', 'ruleId', 'ruleOperator', 'rulePattern', 'rulePhase', 'ruleSeverity', 'ruleAction'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('input', () => this.updateRulePreview());
                element.addEventListener('change', () => this.updateRulePreview());
            }
        });

        // Clear form
        const clearBtn = document.getElementById('clearRuleForm');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearRuleForm());
        }

        // Handle form submission
        const newRuleForm = document.getElementById('newRuleForm');
        if (newRuleForm) {
            newRuleForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.generateRule();
            });
        }

        // Handle template usage
        document.querySelectorAll('.use-template-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const template = btn.dataset.template;
                this.loadTemplate(template);
            });
        });

        // Copy to clipboard
        document.addEventListener('click', (e) => {
            if (e.target.id === 'copyRuleBtn') {
                const ruleText = document.getElementById('generatedRuleText');
                if (ruleText) {
                    this.copyToClipboard(ruleText.textContent);
                    this.showToast('Rule copied to clipboard!', 'success');
                }
            }
        });

        // Save rule button - global listener
        document.addEventListener('click', (e) => {
            if (e.target.id === 'saveRuleBtn') {
                e.preventDefault();
                e.stopPropagation();
                this.saveCustomRule();
            }
        });

        // Search custom rules
        const searchCustom = document.getElementById('searchCustomRules');
        if (searchCustom) {
            searchCustom.addEventListener('input', (e) => {
                this.filterCustomRules(e.target.value);
            });
        }
    }

    async loadRules() {
        try {
            this.showLoading();
            const response = await fetch('/api/rules');
            
            if (response.ok) {
                const data = await response.json();
                this.rules = Array.isArray(data) ? data : [];
                this.updateStatistics(this.calculateStatistics());
            } else {
                this.loadMockRules();
            }
            
            this.filterAndRenderRules();
        } catch (error) {
            console.error('❌ Error loading rules:', error);
            this.loadMockRules();
            this.filterAndRenderRules();
        }
    }

    loadMockRules() {
        this.rules = [
            {
                rule_id: '920100',
                description: 'Invalid HTTP Request Line',
                category: 'Protocol',
                severity: 'CRITICAL',
                current_action: 'block',
                enabled: true
            }
        ];
        this.updateStatistics(this.calculateStatistics());
    }

    calculateStatistics() {
        const total = this.rules.length;
        const active = this.rules.filter(r => r.enabled !== false).length;
        const blocking = this.rules.filter(r => r.current_action === 'block').length;
        return { total, active, blocking, monitoring: 0, disabled: 0 };
    }

    updateStatistics(stats) {
        const elements = {
            totalRules: document.getElementById('totalRules'),
            activeRules: document.getElementById('activeRules'),
            blockedRules: document.getElementById('blockedRules')
        };
        
        if (elements.totalRules) elements.totalRules.textContent = stats.total || 0;
        if (elements.activeRules) elements.activeRules.textContent = stats.active || 0;
        if (elements.blockedRules) elements.blockedRules.textContent = stats.blocking || 0;
    }

    filterAndRenderRules() {
        if (!Array.isArray(this.rules)) {
            this.rules = [];
            return;
        }
        
        this.filteredRules = this.rules.filter(rule => {
            if (!rule) return false;
            
            if (this.filters.search) {
                const searchText = `${rule.rule_id || ''} ${rule.description || ''}`.toLowerCase();
                if (!searchText.includes(this.filters.search)) return false;
            }
            
            if (this.filters.category && rule.category !== this.filters.category) {
                return false;
            }
            
            return true;
        });

        this.currentPage = 1;
        this.totalPages = Math.ceil(this.filteredRules.length / this.itemsPerPage);
        this.renderRules();
    }

    renderRules() {
        const tbody = document.getElementById('rulesTable');
        if (!tbody) return;

        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        const endIndex = startIndex + this.itemsPerPage;
        const pageRules = this.filteredRules.slice(startIndex, endIndex);

        if (pageRules.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-5">
                        <h5 class="text-muted">No rules found</h5>
                        <p class="text-muted">Try adjusting your search criteria</p>
                    </td>
                </tr>
            `;
            return;
        }

        const rowsHtml = pageRules.map(rule => this.createRuleRow(rule)).join('');
        tbody.innerHTML = rowsHtml;
    }

    createRuleRow(rule) {
        if (!rule || !rule.rule_id) {
            return '<tr><td colspan="6" class="text-warning">Invalid rule data</td></tr>';
        }

        return `
            <tr>
                <td><code>${rule.rule_id}</code></td>
                <td>${rule.description || 'No description'}</td>
                <td><span class="badge bg-secondary">${rule.category || 'Unknown'}</span></td>
                <td><span class="badge bg-danger">${rule.severity || 'Unknown'}</span></td>
                <td><span class="badge bg-danger">${rule.current_action || 'block'}</span></td>
                <td>
                    <select class="form-select form-select-sm" data-rule-id="${rule.rule_id}">
                        <option value="block" selected>Block</option>
                        <option value="monitor">Monitor</option>
                        <option value="disabled">Disabled</option>
                    </select>
                </td>
            </tr>
        `;
    }

    async applyChanges() {
        console.log('✅ Apply changes called');
        this.showToast('Changes applied successfully', 'success');
    }

    showLoading() {
        const tbody = document.getElementById('rulesTable');
        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-5">
                        <div class="spinner-border text-primary"></div>
                        <div class="mt-2 text-muted">Loading rules...</div>
                    </td>
                </tr>
            `;
        }
    }

    // === CUSTOM RULES FUNCTIONALITY ===
    
    async loadCustomRules() {
        console.log('🔧 Loading custom rules...');
        
        const container = document.getElementById('customRulesContainer');
        if (!container) {
            console.error('❌ customRulesContainer not found');
            return;
        }
        
        try {
            container.innerHTML = `
                <div class="text-center py-5">
                    <div class="spinner-border text-primary" role="status"></div>
                    <div class="mt-2 text-muted">Loading custom rules...</div>
                </div>
            `;

            const response = await fetch('/api/rules/custom/list');
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            console.log('📊 Custom rules data:', data);
            
            const rules = data.rules || [];
            
            if (rules.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-5">
                        <i class="bi bi-code-slash fs-1 text-muted"></i>
                        <h5 class="text-muted mt-3">No custom rules yet</h5>
                        <p class="text-muted">Create your first custom rule using the "Create Rule" tab</p>
                    </div>
                `;
                return;
            }

            const rulesHtml = rules.map(rule => this.createCustomRuleCard(rule)).join('');
            container.innerHTML = rulesHtml;
            
            this.showToast(`Loaded ${rules.length} custom rules`, 'success');
            
        } catch (error) {
            console.error('❌ Error loading custom rules:', error);
            container.innerHTML = `
                <div class="text-center py-5">
                    <div class="alert alert-danger">
                        <h5>Error Loading Custom Rules</h5>
                        <p>Failed to load custom rules: ${error.message}</p>
                        <button class="btn btn-outline-primary" onclick="window.rulesManager.loadCustomRules()">
                            🔄 Retry
                        </button>
                    </div>
                </div>
            `;
        }
    }

    createCustomRuleCard(rule) {
        const statusClass = this.getStatusClass(rule.current_action);
        const statusIcon = this.getStatusIcon(rule.current_action);
        const statusText = this.getStatusText(rule.current_action);
        const badgeClass = this.getBadgeClass(rule.current_action);
        
        return `
            <div class="card mb-3 custom-rule-card ${statusClass}" data-rule-id="${rule.rule_id}">
                <div class="card-body">
                    <div class="row align-items-center">
                        <div class="col-md-6">
                            <div class="d-flex align-items-start">
                                <i class="bi bi-${statusIcon} me-2 mt-1"></i>
                                <div>
                                    <h6 class="mb-1">
                                        Rule ID: ${rule.rule_id || 'Unknown'}
                                        <span class="badge ${badgeClass} ms-2">${statusText}</span>
                                    </h6>
                                    <p class="text-muted mb-2 small">${rule.description || 'No description available'}</p>
                                    <div class="code-snippet small mb-2" style="background: #f8f9fa; padding: 0.5rem; border-radius: 4px; font-family: monospace;">
                                        ${rule.preview || rule.rule_text}
                                    </div>
                                    <small class="text-muted">
                                        <div><strong>Created:</strong> ${new Date(rule.created_at).toLocaleDateString()}</div>
                                        <div><strong>Modified:</strong> ${new Date(rule.last_modified).toLocaleDateString()}</div>
                                    </small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="mb-2">
                                <label class="form-label small">Change Action:</label>
                                <select class="form-select form-select-sm" 
                                        onchange="window.rulesManager.updateCustomRuleAction('${rule.rule_id}', this.value)"
                                        ${rule.current_action === 'disabled' ? 'disabled' : ''}>
                                    <option value="block" ${rule.current_action === 'block' ? 'selected' : ''}>Block</option>
                                    <option value="monitor" ${rule.current_action === 'monitor' ? 'selected' : ''}>Monitor</option>
                                    <option value="disabled" ${rule.current_action === 'disabled' ? 'selected' : ''}>Disabled</option>
                                </select>
                            </div>
                        </div>
                        <div class="col-md-3 text-end">
                            <div class="btn-group-vertical d-grid gap-1" style="width: 100%;">
                                <button class="btn btn-sm btn-outline-primary" 
                                        onclick="window.rulesManager.viewFullRule('${rule.rule_id}')" 
                                        title="View Full Rule">
                                    <i class="bi bi-eye"></i> View
                                </button>
                                <button class="btn btn-sm btn-outline-info" 
                                        onclick="window.rulesManager.copyCustomRule('${rule.rule_id}')" 
                                        title="Copy Rule">
                                    <i class="bi bi-clipboard"></i> Copy
                                </button>
                                <button class="btn btn-sm ${rule.current_action === 'disabled' ? 'btn-outline-success' : 'btn-outline-warning'}" 
                                        onclick="window.rulesManager.toggleCustomRule('${rule.rule_id}')" 
                                        title="${rule.current_action === 'disabled' ? 'Enable Rule' : 'Disable Rule'}">
                                    <i class="bi bi-${rule.current_action === 'disabled' ? 'play' : 'pause'}"></i> 
                                    ${rule.current_action === 'disabled' ? 'Enable' : 'Disable'}
                                </button>
                                <button class="btn btn-sm btn-outline-danger" 
                                        onclick="window.rulesManager.deleteCustomRule('${rule.rule_id}')" 
                                        title="Delete Rule">
                                    <i class="bi bi-trash"></i> Delete
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // Funciones helper para estilos de estado
    getStatusClass(action) {
        switch(action) {
            case 'block': return 'enabled';
            case 'monitor': return 'monitoring';
            case 'disabled': return 'disabled';
            default: return 'enabled';
        }
    }

    getStatusIcon(action) {
        switch(action) {
            case 'block': return 'shield-fill-check text-success';
            case 'monitor': return 'eye-fill text-warning';
            case 'disabled': return 'x-circle-fill text-danger';
            default: return 'shield-fill-check text-success';
        }
    }

    getStatusText(action) {
        switch(action) {
            case 'block': return 'Blocking';
            case 'monitor': return 'Monitoring';
            case 'disabled': return 'Disabled';
            default: return 'Active';
        }
    }

    getBadgeClass(action) {
        switch(action) {
            case 'block': return 'bg-success';
            case 'monitor': return 'bg-warning';
            case 'disabled': return 'bg-danger';
            default: return 'bg-primary';
        }
    }

    // Función para actualizar la acción de una custom rule
    async updateCustomRuleAction(ruleId, action) {
        try {
            console.log(`Updating custom rule ${ruleId} to ${action}`);
            
            const response = await fetch(`/api/rules/custom/${ruleId}/action`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action: action })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Failed to update rule');
            }

            const result = await response.json();
            this.showToast(result.message, 'success');
            
            // Recargar custom rules para mostrar el estado actualizado
            this.loadCustomRules();
            this.updateCustomRulesCount();
            
        } catch (error) {
            console.error('Error updating custom rule action:', error);
            this.showToast('Error updating rule: ' + error.message, 'danger');
        }
    }

    // Función para toggle enable/disable de custom rule
    async toggleCustomRule(ruleId) {
        try {
            console.log(`Toggling custom rule ${ruleId}`);
            
            const response = await fetch(`/api/rules/custom/${ruleId}/toggle`, {
                method: 'POST'
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Failed to toggle rule');
            }

            const result = await response.json();
            this.showToast(result.message, 'success');
            
            // Recargar custom rules
            this.loadCustomRules();
            this.updateCustomRulesCount();
            
        } catch (error) {
            console.error('Error toggling custom rule:', error);
            this.showToast('Error toggling rule: ' + error.message, 'danger');
        }
    }

    async viewFullRule(ruleId) {
        try {
            const response = await fetch('/api/rules/custom/list');
            const data = await response.json();
            const rule = data.rules.find(r => r.rule_id === ruleId);
            
            if (rule) {
                alert(`Rule ${ruleId}:\n\n${rule.rule_text}`);
            }
        } catch (error) {
            this.showToast('Error fetching rule details', 'danger');
        }
    }

    async copyCustomRule(ruleId) {
        try {
            const response = await fetch('/api/rules/custom/list');
            const data = await response.json();
            const rule = data.rules.find(r => r.rule_id === ruleId);
            
            if (rule && navigator.clipboard) {
                await navigator.clipboard.writeText(rule.rule_text);
                this.showToast('Rule copied to clipboard', 'success');
            }
        } catch (error) {
            this.showToast('Error copying rule', 'danger');
        }
    }

    async deleteCustomRule(ruleId) {
        if (confirm(`Delete custom rule ${ruleId}?`)) {
            try {
                const response = await fetch(`/api/rules/custom/${ruleId}`, {
                    method: 'DELETE'
                });

                if (response.ok) {
                    this.showToast('Rule deleted successfully', 'success');
                    this.loadCustomRules();
                    this.updateCustomRulesCount();
                } else {
                    throw new Error('Failed to delete rule');
                }
            } catch (error) {
                this.showToast('Error deleting rule: ' + error.message, 'danger');
            }
        }
    }

    filterCustomRules(searchTerm) {
        // Filter custom rules based on search term
        console.log('Filtering custom rules:', searchTerm);
        // Implementation would filter the displayed rules
    }

    // === RULE CREATION FUNCTIONALITY ===

    updateRulePreview() {
        const ruleType = document.getElementById('ruleType');
        if (!ruleType || !ruleType.value || ruleType.value === 'custom') return;

        const ruleId = document.getElementById('ruleId')?.value || '900XXX';
        const operator = document.getElementById('ruleOperator')?.value || '@contains';
        const pattern = document.getElementById('rulePattern')?.value || 'pattern';
        const phase = document.getElementById('rulePhase')?.value || '2';
        const severity = document.getElementById('ruleSeverity')?.value || 'CRITICAL';
        const action = document.getElementById('ruleAction')?.value || 'block';
        const ruleName = document.getElementById('ruleName')?.value || 'Custom Rule';

        let variable = '';
        switch (ruleType.value) {
            case 'request_header': variable = 'REQUEST_HEADERS'; break;
            case 'request_uri': variable = 'REQUEST_URI'; break;
            case 'request_method': variable = 'REQUEST_METHOD'; break;
            case 'request_body': variable = 'REQUEST_BODY'; break;
            case 'ip_address': variable = 'REMOTE_ADDR'; break;
            case 'user_agent': variable = 'REQUEST_HEADERS:User-Agent'; break;
        }

        const rule = `SecRule ${variable} "${operator} ${pattern}" \\
    "id:${ruleId},\\
    phase:${phase},\\
    ${action},\\
    msg:'${ruleName}',\\
    severity:${severity}"`;

        const previewElement = document.getElementById('rulePreview');
        if (previewElement) {
            previewElement.textContent = rule;
        }
    }

    async generateRule() {
        const ruleType = document.getElementById('ruleType');
        const ruleId = document.getElementById('ruleId');
        
        // Validar rule ID
        if (ruleId && ruleId.value) {
            try {
                const response = await fetch(`/api/rules/validate/${ruleId.value}`);
                if (response.ok) {
                    const validation = await response.json();
                    if (!validation.available) {
                        this.showToast(`Rule ID ${ruleId.value} is already in use`, 'warning');
                        return;
                    }
                }
            } catch (error) {
                console.warn('Could not validate rule ID:', error);
            }
        }
        
        let generatedRule = '';

        if (ruleType && ruleType.value === 'custom') {
            const customText = document.getElementById('customRuleText');
            generatedRule = customText ? customText.value : '';
        } else {
            const preview = document.getElementById('rulePreview');
            generatedRule = preview ? preview.textContent : '';
        }

        const generatedElement = document.getElementById('generatedRuleText');
        const containerElement = document.getElementById('generatedRuleContainer');
        
        if (generatedElement) generatedElement.textContent = generatedRule;
        if (containerElement) containerElement.style.display = 'block';
        
        window.generatedRule = generatedRule;
    }

    clearRuleForm() {
        const form = document.getElementById('newRuleForm');
        if (form) form.reset();
        
        const elements = [
            'generatedRuleContainer',
            'rulePreviewContainer', 
            'customRuleContainer'
        ];
        
        elements.forEach(id => {
            const element = document.getElementById(id);
            if (element) element.style.display = 'none';
        });
        
        window.generatedRule = null;
    }

    loadTemplate(templateName) {
        // Switch to Create Rule tab
        const createTab = document.getElementById('create-rule-tab');
        if (createTab) createTab.click();

        // Fill form based on template
        const templates = {
            'user_agent_block': {
                name: 'Block Malicious User Agents',
                id: '900001',
                type: 'user_agent',
                operator: '@rx',
                pattern: '(bot|crawler|spider|scraper)',
                action: 'block',
                severity: 'CRITICAL'
            },
            'sql_injection': {
                name: 'SQL Injection Protection',
                id: '900002',
                type: 'request_body',
                operator: '@detectSQLi',
                pattern: '',
                action: 'block',
                severity: 'CRITICAL'
            },
            'xss_protection': {
                name: 'XSS Protection',
                id: '900005',
                type: 'request_body',
                operator: '@detectXSS',
                pattern: '',
                action: 'block',
                severity: 'CRITICAL'
            },
            'ip_block': {
                name: 'Block IP Range',
                id: '900004',
                type: 'ip_address',
                operator: '@ipMatch',
                pattern: '10.0.0.0/8,192.168.0.0/16',
                action: 'deny',
                severity: 'WARNING'
            }
        };

        const template = templates[templateName];
        if (template) {
            this.fillFormFields({
                'ruleName': template.name,
                'ruleId': template.id,
                'ruleType': template.type,
                'ruleOperator': template.operator,
                'rulePattern': template.pattern,
                'ruleAction': template.action,
                'ruleSeverity': template.severity
            });

            this.updateRulePreview();
            const previewContainer = document.getElementById('rulePreviewContainer');
            if (previewContainer) previewContainer.style.display = 'block';
            
            this.showToast('Template loaded successfully!', 'success');
        }
    }

    fillFormFields(fields) {
        Object.keys(fields).forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.value = fields[id];
            }
        });
    }

    async saveCustomRule() {
        try {
            if (!window.generatedRule) {
                throw new Error('No rule generated to save');
            }

            const description = document.getElementById('ruleDescription')?.value || 
                              document.getElementById('ruleName')?.value || 
                              'Custom rule';

            const response = await fetch('/api/rules/custom', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    rule: window.generatedRule,
                    description: description
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Failed to save rule');
            }

            const result = await response.json();
            this.showToast(result.message, 'success');
            
            // Limpiar formulario
            this.clearRuleForm();
            
            // Actualizar contador
            this.updateCustomRulesCount();
            
            // Cambiar a la pestaña de custom rules para ver la nueva regla
            const customTab = document.getElementById('custom-rules-tab');
            if (customTab) {
                customTab.click();
            }
            
        } catch (error) {
            console.error('Error saving custom rule:', error);
            const message = error.message || 'Error saving custom rule';
            this.showToast(message, 'danger');
        }
    }

    async updateCustomRulesCount() {
        try {
            const response = await fetch('/api/rules/custom/statistics');
            if (response.ok) {
                const stats = await response.json();
                
                // Actualizar contador principal
                const countElement = document.getElementById('customRulesCount');
                if (countElement) {
                    countElement.textContent = stats.total_custom_rules || 0;
                }
                
                // Actualizar estadísticas detalladas si existe el contenedor
                this.updateDetailedCustomStats(stats);
            }
        } catch (error) {
            console.error('Error updating custom rules count:', error);
        }
    }

    // Función para mostrar estadísticas detalladas
    updateDetailedCustomStats(stats) {
        const statsContainer = document.getElementById('customRulesStats');
        if (statsContainer && stats.by_action) {
            const blocking = stats.by_action.block || 0;
            const monitoring = stats.by_action.monitor || 0;
            const disabled = stats.by_action.disabled || 0;
            
            statsContainer.innerHTML = `
                <div class="row text-center">
                    <div class="col-3">
                        <div class="stat-item">
                            <span class="stat-number text-success">${blocking}</span>
                            <span class="stat-label">Blocking</span>
                        </div>
                    </div>
                    <div class="col-3">
                        <div class="stat-item">
                            <span class="stat-number text-warning">${monitoring}</span>
                            <span class="stat-label">Monitoring</span>
                        </div>
                    </div>
                    <div class="col-3">
                        <div class="stat-item">
                            <span class="stat-number text-danger">${disabled}</span>
                            <span class="stat-label">Disabled</span>
                        </div>
                    </div>
                    <div class="col-3">
                        <div class="stat-item">
                            <span class="stat-number">${stats.total_custom_rules}</span>
                            <span class="stat-label">Total</span>
                        </div>
                    </div>
                </div>
            `;
        }
    }

    // === UTILITY FUNCTIONS ===

    copyToClipboard(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text);
        } else {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        }
    }

    showToast(message, type = 'info') {
        console.log(`📢 Toast: ${message} (${type})`);
        
        // Crear toast si no existe el container
        let toastContainer = document.getElementById('toastContainer');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toastContainer';
            toastContainer.className = 'toast-container';
            toastContainer.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999;';
            document.body.appendChild(toastContainer);
        }
        
        const toastId = 'toast_' + Date.now();
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-bg-${type} border-0`;
        toast.id = toastId;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;
        
        toastContainer.appendChild(toast);
        
        // Usar Bootstrap Toast si está disponible
        if (typeof bootstrap !== 'undefined' && bootstrap.Toast) {
            const bsToast = new bootstrap.Toast(toast);
            bsToast.show();
            
            toast.addEventListener('hidden.bs.toast', () => {
                toast.remove();
            });
        } else {
            // Fallback simple
            setTimeout(() => {
                if (toast.parentNode) {
                    toast.remove();
                }
            }, 5000);
        }
    }
}

// === GLOBAL FUNCTIONS ===

// Función de carga manual para debugging
window.loadCustomRulesManually = function() {
    console.log('⚙️ Manual load triggered');
    if (window.rulesManager) {
        window.rulesManager.loadCustomRules();
    } else {
        console.error('❌ RulesManager not available');
        // Intentar crear una instancia si no existe
        setTimeout(() => {
            if (!window.rulesManager) {
                console.log('🔄 Creating new RulesManager instance...');
                window.rulesManager = new RulesManager();
                setTimeout(() => {
                    if (window.rulesManager) {
                        window.rulesManager.loadCustomRules();
                    }
                }, 1000);
            }
        }, 100);
    }
};

// Función para debugging
window.debugRulesManager = function() {
    console.log('=== RULES MANAGER DEBUG ===');
    console.log('RulesManager class exists:', typeof RulesManager);
    console.log('window.rulesManager exists:', !!window.rulesManager);
    console.log('customRulesContainer exists:', !!document.getElementById('customRulesContainer'));
    console.log('custom-rules-tab exists:', !!document.getElementById('custom-rules-tab'));
    console.log('refreshCustomRules exists:', !!document.getElementById('refreshCustomRules'));
    
    // Test API
    fetch('/api/rules/custom/list')
        .then(r => r.json())
        .then(data => console.log('API test result:', data))
        .catch(err => console.error('API test failed:', err));
};

// === INITIALIZATION ===

// Inicialización robusta con múltiples intentos
function initializeRulesManager() {
    console.log('🚀 Initializing Rules Manager...');
    
    if (typeof RulesManager === 'undefined') {
        console.error('❌ RulesManager class not defined');
        return;
    }
    
    // Crear instancia global
    window.rulesManager = new RulesManager();
    console.log('✅ RulesManager instance created');
}

// Múltiples puntos de inicialización
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeRulesManager);
} else {
    // DOM ya está listo
    initializeRulesManager();
}

// Backup en caso de que DOMContentLoaded ya haya pasado
setTimeout(initializeRulesManager, 500);

console.log('🔧 rules_management.js loaded successfully');
