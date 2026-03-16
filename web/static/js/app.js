/**
 * DorkMaster - Unified Frontend Application
 * ============================================
 * Combines DorkForge generator + DorkHunter search into one UI.
 * Handles mode switching, API communication, and result management.
 */

(function () {
    'use strict';

    // -- Constants --
    const VIRTUAL_ROW_HEIGHT = 32;
    const VIRTUAL_OVERSCAN = 20;
    const RENDER_CHUNK_LIMIT = 5000;

    // -- Generator State --
    let currentEngine = 'google';
    let allDorks = [];
    let filteredDorks = [];
    let selectedRows = new Set();
    let engineConfig = null;
    let sortAscending = true;
    let useVirtualScroll = false;

    // -- Hunter State --
    let hunterUrls = [];
    let hunterFilteredUrls = [];
    let currentMode = 'generator';

    // -- DOM Helpers --
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const els = {};

    function cacheElements() {
        const ids = [
            // Generator
            'engineSelector', 'keywordsInput', 'keywordFileUpload', 'clearKeywords',
            'operatorGrid', 'filetypeGrid', 'siteInput', 'exclusionsInput',
            'useQuotes', 'generateAll', 'maxResults', 'maxResultsGroup',
            'generateBtn', 'searchInput', 'searchClear',
            'sortBtn', 'shuffleBtn', 'resultsEmpty', 'resultsList', 'resultCount',
            'warningsContainer', 'copyAllBtn', 'copySelectedBtn',
            'exportTxtBtn', 'exportCsvBtn', 'exportJsonBtn',
            'loadingOverlay', 'loadingSubtext', 'loadingText',
            'statPossibleVal', 'statGeneratedVal',
            'keywordCount', 'operatorCount', 'filetypeCount',
            'selectAllOps', 'deselectAllOps', 'selectAllFt', 'deselectAllFt',
            'configPanel', 'resultsPanel', 'resizeHandle', 'resultsBody',
            'sendToHunterBtn',
            // Mode
            'tabGenerator', 'tabHunter', 'modeGenerator', 'modeHunter',
            // Hunter
            'hunterDorksInput', 'hunterDorkCount', 'hunterFileUpload',
            'hunterClearDorks', 'hunterEngineGrid', 'hunterPages',
            'hunterConcurrency', 'hunterSearchBtn',
            'hunterSearchInput', 'hunterSearchClear',
            'hunterResultsEmpty', 'hunterResultsList', 'hunterUrlCount',
            'hunterCopyAllBtn',
            'hunterExportTxtBtn', 'hunterExportCsvBtn', 'hunterExportJsonBtn',
            'hunterConfigPanel', 'hunterResizeHandle', 'hunterResultsBody',
        ];
        ids.forEach((id) => {
            els[id] = document.getElementById(id);
        });
    }

    // -- Initialize --
    async function init() {
        cacheElements();

        try {
            const resp = await fetch('/api/config');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            engineConfig = await resp.json();
        } catch (e) {
            console.error('Failed to load config:', e);
            toast('Failed to load configuration. Please refresh.', 'error');
            return;
        }

        setupModeTabs();
        setupEngineSelector();
        renderOperators();
        renderFiletypes();
        bindGeneratorEvents();
        bindHunterEvents();
        setupPanelResize();
        updateCounts();
        syncGenerateAllUI();
    }

    // ================================================================
    // MODE SWITCHING
    // ================================================================

    function setupModeTabs() {
        els.tabGenerator?.addEventListener('click', () => switchMode('generator'));
        els.tabHunter?.addEventListener('click', () => switchMode('hunter'));
    }

    function switchMode(mode) {
        currentMode = mode;

        // Update tabs
        $$('.mode-tab').forEach(t => t.classList.remove('mode-tab--active'));
        if (mode === 'generator') {
            els.tabGenerator?.classList.add('mode-tab--active');
        } else {
            els.tabHunter?.classList.add('mode-tab--active');
        }

        // Update content
        $$('.mode-content').forEach(c => c.classList.remove('mode-content--active'));
        if (mode === 'generator') {
            els.modeGenerator?.classList.add('mode-content--active');
        } else {
            els.modeHunter?.classList.add('mode-content--active');
        }
    }

    // ================================================================
    // GENERATOR
    // ================================================================

    function setupEngineSelector() {
        const options = $$('.engine-option');
        options.forEach((opt) => {
            opt.addEventListener('click', () => {
                options.forEach((o) => o.classList.remove('engine-option--active'));
                opt.classList.add('engine-option--active');
                currentEngine = opt.dataset.engine;
                opt.querySelector('input').checked = true;
                renderOperators();
                renderFiletypes();
                updateCounts();
            });
        });
    }

    function renderOperators() {
        const eng = engineConfig?.engines?.[currentEngine];
        if (!eng || !els.operatorGrid) return;

        els.operatorGrid.innerHTML = '';
        const ops = eng.operators;

        Object.keys(ops).forEach((key) => {
            const op = ops[key];
            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'chip';
            chip.dataset.operator = key;
            chip.textContent = key + ':';
            chip.title = op.description || key;
            chip.setAttribute('role', 'checkbox');
            chip.setAttribute('aria-checked', 'false');
            chip.addEventListener('click', () => {
                chip.classList.toggle('chip--active');
                chip.setAttribute('aria-checked', chip.classList.contains('chip--active'));
                updateCounts();
            });
            els.operatorGrid.appendChild(chip);
        });
    }

    function renderFiletypes() {
        const eng = engineConfig?.engines?.[currentEngine];
        if (!eng || !els.filetypeGrid) return;

        els.filetypeGrid.innerHTML = '';
        const fts = eng.filetypes || [];

        fts.forEach((ft) => {
            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = 'chip';
            chip.dataset.filetype = ft;
            chip.textContent = '.' + ft;
            chip.setAttribute('role', 'checkbox');
            chip.setAttribute('aria-checked', 'false');
            chip.addEventListener('click', () => {
                chip.classList.toggle('chip--active');
                chip.setAttribute('aria-checked', chip.classList.contains('chip--active'));
                updateCounts();
            });
            els.filetypeGrid.appendChild(chip);
        });
    }

    function bindGeneratorEvents() {
        els.generateBtn?.addEventListener('click', generate);
        els.keywordsInput?.addEventListener('input', updateCounts);
        els.keywordFileUpload?.addEventListener('change', handleFileUpload);

        els.clearKeywords?.addEventListener('click', () => {
            if (els.keywordsInput) els.keywordsInput.value = '';
            updateCounts();
        });

        $$('.preset-btn').forEach((btn) => {
            btn.addEventListener('click', () => {
                const kws = btn.dataset.keywords.split('||');
                if (!els.keywordsInput) return;
                const current = els.keywordsInput.value.trim();
                els.keywordsInput.value = current
                    ? current + '\n' + kws.join('\n')
                    : kws.join('\n');
                updateCounts();
                toast(`Added ${kws.length} keywords from preset`);
            });
        });

        els.selectAllOps?.addEventListener('click', () => toggleAll(els.operatorGrid, true));
        els.deselectAllOps?.addEventListener('click', () => toggleAll(els.operatorGrid, false));
        els.selectAllFt?.addEventListener('click', () => toggleAll(els.filetypeGrid, true));
        els.deselectAllFt?.addEventListener('click', () => toggleAll(els.filetypeGrid, false));

        els.generateAll?.addEventListener('change', syncGenerateAllUI);

        els.searchInput?.addEventListener('input', () => {
            applyFilter();
            if (els.searchClear) {
                els.searchClear.style.display = els.searchInput.value ? 'block' : 'none';
            }
        });

        els.searchClear?.addEventListener('click', () => {
            if (els.searchInput) els.searchInput.value = '';
            if (els.searchClear) els.searchClear.style.display = 'none';
            applyFilter();
        });

        els.sortBtn?.addEventListener('click', sortResults);
        els.shuffleBtn?.addEventListener('click', shuffleResults);

        els.copyAllBtn?.addEventListener('click', copyAll);
        els.copySelectedBtn?.addEventListener('click', copySelected);

        els.exportTxtBtn?.addEventListener('click', () => exportDorks('txt'));
        els.exportCsvBtn?.addEventListener('click', () => exportDorks('csv'));
        els.exportJsonBtn?.addEventListener('click', () => exportDorks('json'));

        // Send to Hunter
        els.sendToHunterBtn?.addEventListener('click', () => {
            if (filteredDorks.length === 0) return;
            if (els.hunterDorksInput) {
                els.hunterDorksInput.value = filteredDorks.join('\n');
                updateHunterDorkCount();
            }
            switchMode('hunter');
            toast(`Sent ${filteredDorks.length} dorks to Hunter`);
        });

        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                if (currentMode === 'generator') {
                    generate();
                } else {
                    hunterSearch();
                }
            }
            if (e.key === 'Escape') {
                if (document.activeElement === els.searchInput) {
                    els.searchInput.value = '';
                    if (els.searchClear) els.searchClear.style.display = 'none';
                    applyFilter();
                    els.searchInput.blur();
                }
                if (document.activeElement === els.hunterSearchInput) {
                    els.hunterSearchInput.value = '';
                    if (els.hunterSearchClear) els.hunterSearchClear.style.display = 'none';
                    applyHunterFilter();
                    els.hunterSearchInput.blur();
                }
            }
        });
    }

    function syncGenerateAllUI() {
        const checked = els.generateAll?.checked || false;
        if (els.maxResults) {
            els.maxResults.disabled = checked;
            if (checked) {
                els.maxResults.dataset.prevValue = els.maxResults.value;
                els.maxResults.value = '0';
            } else {
                els.maxResults.value = els.maxResults.dataset.prevValue || '100';
            }
        }
    }

    function setupPanelResize() {
        setupResize(els.resizeHandle, els.configPanel);
        setupResize(els.hunterResizeHandle, els.hunterConfigPanel);
    }

    function setupResize(handle, panel) {
        if (!handle || !panel) return;
        let isResizing = false;
        let startX = 0;
        let startWidth = 0;

        handle.addEventListener('mousedown', (e) => {
            isResizing = true;
            startX = e.clientX;
            startWidth = panel.offsetWidth;
            handle.classList.add('resize-handle--active');
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
            e.preventDefault();
        });

        document.addEventListener('mousemove', (e) => {
            if (!isResizing) return;
            const diff = e.clientX - startX;
            const newWidth = Math.max(300, Math.min(520, startWidth + diff));
            panel.style.width = newWidth + 'px';
        });

        document.addEventListener('mouseup', () => {
            if (isResizing) {
                isResizing = false;
                handle.classList.remove('resize-handle--active');
                document.body.style.cursor = '';
                document.body.style.userSelect = '';
            }
        });
    }

    function handleFileUpload(e) {
        const file = e.target.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => {
            const text = ev.target.result;
            const lines = text.split('\n').filter((l) => l.trim());
            if (!els.keywordsInput) return;
            const current = els.keywordsInput.value.trim();
            els.keywordsInput.value = current
                ? current + '\n' + lines.join('\n')
                : lines.join('\n');
            updateCounts();
            toast(`Loaded ${lines.length} keywords from file`);
        };
        reader.onerror = () => toast('Failed to read file', 'error');
        reader.readAsText(file);
        e.target.value = '';
    }

    function toggleAll(grid, active) {
        if (!grid) return;
        grid.querySelectorAll('.chip').forEach((c) => {
            if (active) {
                c.classList.add('chip--active');
                c.setAttribute('aria-checked', 'true');
            } else {
                c.classList.remove('chip--active');
                c.setAttribute('aria-checked', 'false');
            }
        });
        updateCounts();
    }

    function updateCounts() {
        const keywords = getKeywords();
        if (els.keywordCount) els.keywordCount.textContent = keywords.length;

        const ops = getSelectedOperators();
        if (els.operatorCount) els.operatorCount.textContent = ops.length;

        const fts = getSelectedFiletypes();
        if (els.filetypeCount) els.filetypeCount.textContent = fts.length;

        const kLen = keywords.length;
        const nonFtOps = ops.filter((o) => o !== 'filetype' && o !== 'ext' && o !== 'mime');
        const oLen = nonFtOps.length;
        const fLen = fts.length;
        let possible = 0;

        if (oLen > 0 && fLen > 0) {
            possible += oLen * kLen * fLen;
            possible += kLen * fLen;
            if (oLen >= 2) {
                const pairs = oLen * (oLen - 1) / 2;
                possible += pairs * kLen;
                possible += pairs * kLen * fLen;
            }
        } else if (oLen > 0) {
            possible += oLen * kLen;
            if (oLen >= 2) {
                const pairs = oLen * (oLen - 1) / 2;
                possible += pairs * kLen;
            }
        } else if (fLen > 0) {
            possible += kLen * fLen;
        } else {
            possible += kLen;
        }

        if (els.statPossibleVal) els.statPossibleVal.textContent = possible.toLocaleString();
    }

    function getKeywords() {
        if (!els.keywordsInput) return [];
        return els.keywordsInput.value.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
    }

    function getSelectedOperators() {
        if (!els.operatorGrid) return [];
        return Array.from(els.operatorGrid.querySelectorAll('.chip--active')).map((c) => c.dataset.operator);
    }

    function getSelectedFiletypes() {
        if (!els.filetypeGrid) return [];
        return Array.from(els.filetypeGrid.querySelectorAll('.chip--active')).map((c) => c.dataset.filetype);
    }

    async function generate() {
        const keywords = getKeywords();
        if (keywords.length === 0) {
            toast('Please enter at least one keyword', 'warning');
            els.keywordsInput?.focus();
            return;
        }

        const generateAllChecked = els.generateAll?.checked || false;
        let maxResultsVal = parseInt(els.maxResults?.value, 10);
        if (isNaN(maxResultsVal) || maxResultsVal < 0) maxResultsVal = 100;
        if (generateAllChecked) maxResultsVal = 0;

        const payload = {
            engine: currentEngine,
            keywords: keywords,
            operators: getSelectedOperators(),
            filetypes: getSelectedFiletypes(),
            site: els.siteInput?.value.trim() || '',
            use_quotes: els.useQuotes?.checked || false,
            exclusions: (els.exclusionsInput?.value || '').split('\n').map((l) => l.trim()).filter((l) => l),
            max_results: maxResultsVal,
        };

        showLoading('Generating dorks...', maxResultsVal === 0
            ? 'Generating ALL combinations - this may take a moment...'
            : 'This may take a moment for large queries');
        if (els.generateBtn) els.generateBtn.disabled = true;

        try {
            const resp = await fetch('/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

            if (!resp.ok) throw new Error(`Server error (HTTP ${resp.status})`);
            const result = await resp.json();

            if (result.error) {
                toast(result.error, 'error');
                return;
            }

            allDorks = result.dorks || [];
            filteredDorks = [...allDorks];
            selectedRows.clear();
            useVirtualScroll = filteredDorks.length > RENDER_CHUNK_LIMIT;

            if (els.statGeneratedVal) els.statGeneratedVal.textContent = result.total_generated.toLocaleString();
            if (els.statPossibleVal) els.statPossibleVal.textContent = result.total_possible.toLocaleString();

            if (result.warnings?.length > 0) {
                if (els.warningsContainer) {
                    els.warningsContainer.style.display = 'block';
                    els.warningsContainer.innerHTML = result.warnings.map((w) => `<div class="warning-item">${escapeHtml(w)}</div>`).join('');
                }
            } else {
                if (els.warningsContainer) els.warningsContainer.style.display = 'none';
            }

            renderResults();
            updateButtons();

            if (allDorks.length > 0) {
                toast(`Generated ${allDorks.length.toLocaleString()} dorks for ${result.engine_name}`);
            } else {
                toast('No dorks generated. Try different options.', 'warning');
            }
        } catch (e) {
            toast('Generation failed: ' + e.message, 'error');
        } finally {
            hideLoading();
            if (els.generateBtn) els.generateBtn.disabled = false;
        }
    }

    function renderResults() {
        if (els.searchInput) els.searchInput.value = '';
        if (els.searchClear) els.searchClear.style.display = 'none';
        renderFilteredResults();
    }

    function renderFilteredResults() {
        if (filteredDorks.length === 0) {
            if (els.resultsEmpty) els.resultsEmpty.style.display = 'flex';
            if (els.resultsList) els.resultsList.style.display = 'none';
            if (els.resultCount) els.resultCount.textContent = '0 dorks';
            return;
        }

        if (els.resultsEmpty) els.resultsEmpty.style.display = 'none';
        if (els.resultsList) els.resultsList.style.display = 'block';

        if (useVirtualScroll) {
            renderVirtual();
        } else {
            renderDirect();
        }

        if (els.resultCount) {
            els.resultCount.textContent = `${filteredDorks.length.toLocaleString()} dorks`;
        }
    }

    function renderDirect() {
        const frag = document.createDocumentFragment();
        filteredDorks.forEach((dork, idx) => {
            frag.appendChild(createDorkRow(dork, idx + 1));
        });
        if (els.resultsList) {
            els.resultsList.innerHTML = '';
            els.resultsList.className = 'results-list';
            els.resultsList.appendChild(frag);
        }
        if (els.resultsBody) els.resultsBody.onscroll = null;
    }

    function renderVirtual() {
        if (!els.resultsList || !els.resultsBody) return;
        els.resultsList.innerHTML = '';
        els.resultsList.className = 'results-list results-list--virtual';
        const totalHeight = filteredDorks.length * VIRTUAL_ROW_HEIGHT;
        els.resultsList.style.height = totalHeight + 'px';
        els.resultsList.style.position = 'relative';

        const renderVisibleRows = () => {
            const scrollTop = els.resultsBody.scrollTop;
            const viewHeight = els.resultsBody.clientHeight;
            const startIdx = Math.max(0, Math.floor(scrollTop / VIRTUAL_ROW_HEIGHT) - VIRTUAL_OVERSCAN);
            const endIdx = Math.min(filteredDorks.length, Math.ceil((scrollTop + viewHeight) / VIRTUAL_ROW_HEIGHT) + VIRTUAL_OVERSCAN);

            const existing = els.resultsList.querySelectorAll('.dork-row');
            existing.forEach((row) => {
                const rowIdx = parseInt(row.dataset.virtualIndex, 10);
                if (rowIdx < startIdx || rowIdx >= endIdx) row.remove();
            });

            const existingIndices = new Set();
            els.resultsList.querySelectorAll('.dork-row').forEach((row) => {
                existingIndices.add(parseInt(row.dataset.virtualIndex, 10));
            });

            const frag = document.createDocumentFragment();
            for (let i = startIdx; i < endIdx; i++) {
                if (existingIndices.has(i)) continue;
                const row = createDorkRow(filteredDorks[i], i + 1);
                row.style.position = 'absolute';
                row.style.top = (i * VIRTUAL_ROW_HEIGHT) + 'px';
                row.style.left = '0';
                row.style.right = '0';
                row.style.height = VIRTUAL_ROW_HEIGHT + 'px';
                row.dataset.virtualIndex = i;
                frag.appendChild(row);
            }
            els.resultsList.appendChild(frag);
        };

        renderVisibleRows();
        els.resultsBody.onscroll = renderVisibleRows;
    }

    function createDorkRow(dork, num) {
        const row = document.createElement('div');
        row.className = 'dork-row';
        row.dataset.index = num - 1;

        const numEl = document.createElement('div');
        numEl.className = 'dork-row__num';
        numEl.textContent = num;

        const textEl = document.createElement('div');
        textEl.className = 'dork-row__text';
        textEl.innerHTML = highlightDork(dork);

        const copyEl = document.createElement('button');
        copyEl.type = 'button';
        copyEl.className = 'dork-row__copy';
        copyEl.textContent = '\u{1F4CB}';
        copyEl.title = 'Copy this dork';
        copyEl.addEventListener('click', (e) => {
            e.stopPropagation();
            copyToClipboard(dork);
            toast('Copied to clipboard');
        });

        row.addEventListener('click', () => {
            const idx = parseInt(row.dataset.index, 10);
            if (selectedRows.has(idx)) {
                selectedRows.delete(idx);
                row.classList.remove('dork-row--selected');
            } else {
                selectedRows.add(idx);
                row.classList.add('dork-row--selected');
            }
            updateButtons();
        });

        row.appendChild(numEl);
        row.appendChild(textEl);
        row.appendChild(copyEl);
        return row;
    }

    function highlightDork(dork) {
        let html = escapeHtml(dork);
        html = html.replace(/\b([\w.]+):(&quot;[^&]*&quot;)/gi, (match, op, val) => {
            const opLower = op.toLowerCase();
            if (['filetype', 'ext', 'mime'].includes(opLower)) return `<span class="op">${op}:</span><span class="ft">${val}</span>`;
            return `<span class="op">${op}:</span><span class="qt">${val}</span>`;
        });
        html = html.replace(/\b([\w.]+):(\S+)/gi, (match, op, val) => {
            if (match.includes('<span')) return match;
            const opLower = op.toLowerCase();
            if (['filetype', 'ext', 'mime'].includes(opLower)) return `<span class="op">${op}:</span><span class="ft">${val}</span>`;
            return `<span class="op">${op}:</span><span class="kw">${val}</span>`;
        });
        html = html.replace(/\b(in:\w+)\s+(\S+)/gi, (match, op, val) => {
            if (match.includes('<span')) return match;
            return `<span class="op">${op}</span> <span class="kw">${val}</span>`;
        });
        html = html.replace(/(?<![:\w])(&quot;[^&]*&quot;)/g, '<span class="qt">$1</span>');
        html = html.replace(/(^|\s)(-\S+)/g, '$1<span class="neg">$2</span>');
        html = html.replace(/(^|\s)(NOT\s+\S+)/g, '$1<span class="neg">$2</span>');
        html = html.replace(/(^|\s)(~~\S+)/g, '$1<span class="neg">$2</span>');
        return html.trim();
    }

    function applyFilter() {
        const term = els.searchInput?.value.trim().toLowerCase() || '';
        if (!term) {
            filteredDorks = [...allDorks];
        } else {
            filteredDorks = allDorks.filter((d) => d.toLowerCase().includes(term));
        }
        useVirtualScroll = filteredDorks.length > RENDER_CHUNK_LIMIT;
        selectedRows.clear();
        renderFilteredResults();
        updateButtons();
    }

    function sortResults() {
        if (sortAscending) {
            filteredDorks.sort((a, b) => a.localeCompare(b));
        } else {
            filteredDorks.sort((a, b) => b.localeCompare(a));
        }
        sortAscending = !sortAscending;
        if (els.sortBtn) els.sortBtn.textContent = sortAscending ? 'A-Z' : 'Z-A';
        selectedRows.clear();
        renderFilteredResults();
        updateButtons();
    }

    function shuffleResults() {
        for (let i = filteredDorks.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [filteredDorks[i], filteredDorks[j]] = [filteredDorks[j], filteredDorks[i]];
        }
        selectedRows.clear();
        renderFilteredResults();
        updateButtons();
    }

    function copyAll() {
        if (filteredDorks.length === 0) return;
        copyToClipboard(filteredDorks.join('\n'));
        toast(`Copied ${filteredDorks.length.toLocaleString()} dorks`);
    }

    function copySelected() {
        if (selectedRows.size === 0) return;
        const selected = [...selectedRows].sort((a, b) => a - b).map((idx) => filteredDorks[idx]).filter(Boolean);
        copyToClipboard(selected.join('\n'));
        toast(`Copied ${selected.length} selected dorks`);
    }

    async function exportDorks(format) {
        if (filteredDorks.length === 0) return;
        const eng = engineConfig?.engines?.[currentEngine];
        const engineName = eng?.name || currentEngine;
        try {
            const resp = await fetch('/api/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ dorks: filteredDorks, format: format, engine_name: engineName }),
            });
            if (!resp.ok) throw new Error(`Export failed (HTTP ${resp.status})`);
            const blob = await resp.blob();
            downloadBlob(blob, `dorkmaster_export.${format}`);
            toast(`Exported ${filteredDorks.length.toLocaleString()} dorks as ${format.toUpperCase()}`);
        } catch (e) {
            toast('Export failed: ' + e.message, 'error');
        }
    }

    function updateButtons() {
        const hasDorks = filteredDorks.length > 0;
        const hasSelected = selectedRows.size > 0;
        if (els.copyAllBtn) els.copyAllBtn.disabled = !hasDorks;
        if (els.copySelectedBtn) els.copySelectedBtn.disabled = !hasSelected;
        if (els.exportTxtBtn) els.exportTxtBtn.disabled = !hasDorks;
        if (els.exportCsvBtn) els.exportCsvBtn.disabled = !hasDorks;
        if (els.exportJsonBtn) els.exportJsonBtn.disabled = !hasDorks;
        if (els.sendToHunterBtn) els.sendToHunterBtn.disabled = !hasDorks;
    }

    // ================================================================
    // HUNTER
    // ================================================================

    function bindHunterEvents() {
        els.hunterSearchBtn?.addEventListener('click', hunterSearch);

        els.hunterDorksInput?.addEventListener('input', updateHunterDorkCount);

        els.hunterFileUpload?.addEventListener('change', (e) => {
            const file = e.target.files?.[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (ev) => {
                const lines = ev.target.result.split('\n').filter((l) => l.trim());
                if (!els.hunterDorksInput) return;
                const current = els.hunterDorksInput.value.trim();
                els.hunterDorksInput.value = current ? current + '\n' + lines.join('\n') : lines.join('\n');
                updateHunterDorkCount();
                toast(`Loaded ${lines.length} dorks from file`);
            };
            reader.readAsText(file);
            e.target.value = '';
        });

        els.hunterClearDorks?.addEventListener('click', () => {
            if (els.hunterDorksInput) els.hunterDorksInput.value = '';
            updateHunterDorkCount();
        });

        // Engine chips
        if (els.hunterEngineGrid) {
            els.hunterEngineGrid.querySelectorAll('.chip').forEach((chip) => {
                chip.addEventListener('click', () => {
                    chip.classList.toggle('chip--active');
                });
            });
        }

        // Search filter
        els.hunterSearchInput?.addEventListener('input', () => {
            applyHunterFilter();
            if (els.hunterSearchClear) {
                els.hunterSearchClear.style.display = els.hunterSearchInput.value ? 'block' : 'none';
            }
        });

        els.hunterSearchClear?.addEventListener('click', () => {
            if (els.hunterSearchInput) els.hunterSearchInput.value = '';
            if (els.hunterSearchClear) els.hunterSearchClear.style.display = 'none';
            applyHunterFilter();
        });

        // Copy & Export
        els.hunterCopyAllBtn?.addEventListener('click', () => {
            if (hunterFilteredUrls.length === 0) return;
            copyToClipboard(hunterFilteredUrls.join('\n'));
            toast(`Copied ${hunterFilteredUrls.length} URLs`);
        });

        els.hunterExportTxtBtn?.addEventListener('click', () => exportHunterUrls('txt'));
        els.hunterExportCsvBtn?.addEventListener('click', () => exportHunterUrls('csv'));
        els.hunterExportJsonBtn?.addEventListener('click', () => exportHunterUrls('json'));
    }

    function updateHunterDorkCount() {
        if (!els.hunterDorksInput || !els.hunterDorkCount) return;
        const count = els.hunterDorksInput.value.split('\n').filter(l => l.trim()).length;
        els.hunterDorkCount.textContent = count;
    }

    function getHunterEngines() {
        if (!els.hunterEngineGrid) return ['duckduckgo', 'bing'];
        return Array.from(els.hunterEngineGrid.querySelectorAll('.chip--active')).map(c => c.dataset.engine);
    }

    async function hunterSearch() {
        if (!els.hunterDorksInput) return;
        const dorks = els.hunterDorksInput.value.split('\n').map(l => l.trim()).filter(l => l);
        if (dorks.length === 0) {
            toast('Please enter at least one dork query', 'warning');
            els.hunterDorksInput?.focus();
            return;
        }

        const engines = getHunterEngines();
        if (engines.length === 0) {
            toast('Please select at least one search engine', 'warning');
            return;
        }

        const pages = parseInt(els.hunterPages?.value, 10) || 1;
        const concurrency = parseInt(els.hunterConcurrency?.value, 10) || 3;

        showLoading('Hunting URLs...', `Searching ${dorks.length} dorks across ${engines.length} engines...`);
        if (els.hunterSearchBtn) els.hunterSearchBtn.disabled = true;

        try {
            const resp = await fetch('/api/hunter/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    dorks: dorks,
                    engines: engines,
                    pages_per_dork: pages,
                    max_concurrency: concurrency,
                }),
            });

            if (!resp.ok) throw new Error(`Server error (HTTP ${resp.status})`);
            const result = await resp.json();

            if (result.error) {
                toast(result.error, 'error');
                return;
            }

            hunterUrls = result.urls || [];
            hunterFilteredUrls = [...hunterUrls];

            renderHunterResults();
            updateHunterButtons();

            if (hunterUrls.length > 0) {
                toast(`Extracted ${hunterUrls.length} URLs from ${result.dorks_processed} dorks`);
            } else {
                toast('No URLs extracted. Try different dorks or engines.', 'warning');
            }
        } catch (e) {
            toast('Hunt failed: ' + e.message, 'error');
        } finally {
            hideLoading();
            if (els.hunterSearchBtn) els.hunterSearchBtn.disabled = false;
        }
    }

    function renderHunterResults() {
        if (hunterFilteredUrls.length === 0) {
            if (els.hunterResultsEmpty) els.hunterResultsEmpty.style.display = 'flex';
            if (els.hunterResultsList) els.hunterResultsList.style.display = 'none';
            if (els.hunterUrlCount) els.hunterUrlCount.textContent = '0 URLs';
            return;
        }

        if (els.hunterResultsEmpty) els.hunterResultsEmpty.style.display = 'none';
        if (els.hunterResultsList) els.hunterResultsList.style.display = 'block';

        const frag = document.createDocumentFragment();
        hunterFilteredUrls.forEach((url, idx) => {
            frag.appendChild(createUrlRow(url, idx + 1));
        });

        if (els.hunterResultsList) {
            els.hunterResultsList.innerHTML = '';
            els.hunterResultsList.appendChild(frag);
        }

        if (els.hunterUrlCount) {
            els.hunterUrlCount.textContent = `${hunterFilteredUrls.length.toLocaleString()} URLs`;
        }
    }

    function createUrlRow(url, num) {
        const row = document.createElement('div');
        row.className = 'url-row';

        const numEl = document.createElement('div');
        numEl.className = 'url-row__num';
        numEl.textContent = num;

        const textEl = document.createElement('div');
        textEl.className = 'url-row__text';
        const a = document.createElement('a');
        a.href = url;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = url;
        textEl.appendChild(a);

        const copyEl = document.createElement('button');
        copyEl.type = 'button';
        copyEl.className = 'url-row__copy';
        copyEl.textContent = '\u{1F4CB}';
        copyEl.title = 'Copy URL';
        copyEl.addEventListener('click', (e) => {
            e.stopPropagation();
            copyToClipboard(url);
            toast('URL copied');
        });

        row.appendChild(numEl);
        row.appendChild(textEl);
        row.appendChild(copyEl);
        return row;
    }

    function applyHunterFilter() {
        const term = els.hunterSearchInput?.value.trim().toLowerCase() || '';
        if (!term) {
            hunterFilteredUrls = [...hunterUrls];
        } else {
            hunterFilteredUrls = hunterUrls.filter(u => u.toLowerCase().includes(term));
        }
        renderHunterResults();
        updateHunterButtons();
    }

    function updateHunterButtons() {
        const hasUrls = hunterFilteredUrls.length > 0;
        if (els.hunterCopyAllBtn) els.hunterCopyAllBtn.disabled = !hasUrls;
        if (els.hunterExportTxtBtn) els.hunterExportTxtBtn.disabled = !hasUrls;
        if (els.hunterExportCsvBtn) els.hunterExportCsvBtn.disabled = !hasUrls;
        if (els.hunterExportJsonBtn) els.hunterExportJsonBtn.disabled = !hasUrls;
    }

    async function exportHunterUrls(format) {
        if (hunterFilteredUrls.length === 0) return;
        try {
            const resp = await fetch('/api/hunter/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls: hunterFilteredUrls, format: format }),
            });
            if (!resp.ok) throw new Error(`Export failed (HTTP ${resp.status})`);
            const blob = await resp.blob();
            downloadBlob(blob, `dorkmaster_urls.${format}`);
            toast(`Exported ${hunterFilteredUrls.length} URLs as ${format.toUpperCase()}`);
        } catch (e) {
            toast('Export failed: ' + e.message, 'error');
        }
    }

    // ================================================================
    // SHARED UTILITIES
    // ================================================================

    function showLoading(title, subtitle) {
        if (els.loadingOverlay) els.loadingOverlay.style.display = 'flex';
        if (els.loadingText) els.loadingText.textContent = title || 'Processing...';
        if (els.loadingSubtext) els.loadingSubtext.textContent = subtitle || 'This may take a moment';
    }

    function hideLoading() {
        if (els.loadingOverlay) els.loadingOverlay.style.display = 'none';
    }

    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
        } catch {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;';
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch { /* ignore */ }
            document.body.removeChild(ta);
        }
    }

    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function toast(message, type) {
        type = type || 'success';
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();
        const el = document.createElement('div');
        el.className = 'toast';
        el.setAttribute('role', 'alert');
        el.textContent = message;
        if (type === 'warning') el.style.background = 'var(--warning)';
        else if (type === 'error') el.style.background = 'var(--error)';
        document.body.appendChild(el);
        setTimeout(() => { if (el.parentNode) el.remove(); }, 2700);
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    // -- Boot --
    document.addEventListener('DOMContentLoaded', init);
})();
