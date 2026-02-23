/**
 * AdvancedHunter.js - Microsoft Defender XDR Advanced Hunting Bookmarklet
 * 
 * This script creates a draggable, resizable modal interface for quickly
 * executing KQL queries with variable substitution in Microsoft Defender XDR.
 * 
 * USAGE:
 * 1. Host this file on GitHub Pages or any web server
 * 2. Use the loader bookmarklet to inject this script
 * 3. Enter key=value pairs (one per line)
 * 4. Select a matching query from the filtered list
 * 5. Click Submit to execute the query
 * 
 * ADDING NEW QUERIES:
 * Add entries to the QUERY_LIBRARY array below. Each query needs:
 *   - name: Display name for the query
 *   - requiredKvps: Array of required KVP keys (lowercase)
 *   - template: KQL query with {{key}} placeholders for substitution
 */

(function() {
    'use strict';

    // ========================================================================== 
    // QUERY LIBRARY - Loaded at runtime from external JSON
    // ========================================================================== 
    let QUERY_LIBRARY = null;
    const QUERY_LIBRARY_URL = 'https://raw.githubusercontent.com/Suhailr-CS/AdvancedHunter/main/docs/QueryLibrary.json';

    // ==========================================================================
    // STYLES - Cybersecurity/SOAR themed color palette
    // ==========================================================================
    
    const STYLES = `
        .ah-modal {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 600px;
            min-width: 400px;
            min-height: 400px;
            background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 100%);
            border: 1px solid #00d9ff;
            border-radius: 12px;
            box-shadow: 0 0 30px rgba(0, 217, 255, 0.3), 0 10px 40px rgba(0, 0, 0, 0.5);
            z-index: 999999;
            font-family: 'Segoe UI', 'Roboto', sans-serif;
            color: #e0e0e0;
            overflow: hidden;
            resize: both;
            display: flex;
            flex-direction: column;
            height: 600px;
            max-height: 90vh;
        }
        
        .ah-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            background: linear-gradient(90deg, #1b3a4b 0%, #0d1b2a 100%);
            border-bottom: 1px solid #00d9ff;
            cursor: move;
            user-select: none;
        }
        
        .ah-title {
            font-size: 18px;
            font-weight: 600;
            color: #00d9ff;
            text-shadow: 0 0 10px rgba(0, 217, 255, 0.5);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .ah-title-icon {
            font-size: 22px;
        }
        
        .ah-close-btn {
            background: none;
            border: none;
            color: #ff4757;
            font-size: 24px;
            cursor: pointer;
            padding: 5px;
            line-height: 1;
            transition: all 0.2s ease;
        }
        
        .ah-close-btn:hover {
            color: #ff6b7a;
            text-shadow: 0 0 10px rgba(255, 71, 87, 0.5);
        }
        
        .ah-body {
            padding: 20px 0;
            display: flex;
            flex-direction: column;
            flex: 1 1 auto;
            min-height: 0;
            overflow: hidden;
        }
        
        .ah-section {
            display: flex;
            flex-direction: column;
            gap: 8px;
            width: 100%;
            box-sizing: border-box;
            padding: 0 20px;
        }

        .ah-section.kvp-section {
            flex: 1 1 0;
            min-height: 0;
            margin-bottom: 0;
        }

        .ah-section.results-section {
            flex: 1 1 0;
            min-height: 0;
        }
        
        .ah-section-label {
            font-size: 13px;
            font-weight: 500;
            color: #64dfdf;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .ah-kvp-input {
            width: 100%;
            height: 100%;
            min-height: 0;
            flex: 1 1 0;
            padding: 12px;
            background: #0a1628;
            border: 1px solid #2d4a5e;
            border-radius: 8px;
            color: #e0e0e0;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            resize: none;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
            box-sizing: border-box;
        }
        
        .ah-kvp-input:focus {
            outline: none;
            border-color: #00d9ff;
            box-shadow: 0 0 15px rgba(0, 217, 255, 0.2);
        }
        
        .ah-kvp-input::placeholder {
            color: #5a6a7a;
        }
        
        .ah-results-container {
            flex: 1 1 0;
            min-height: 0;
            background: #0a1628;
            border: 1px solid #2d4a5e;
            border-radius: 8px;
            overflow-y: auto;
            width: 100%;
            box-sizing: border-box;
        }
        
        .ah-results-empty {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: #5a6a7a;
            font-style: italic;
            padding: 20px;
            text-align: center;
        }
        
        .ah-query-item {
            padding: 12px 15px;
            border-bottom: 1px solid #1b3a4b;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .ah-query-item:last-child {
            border-bottom: none;
        }
        
        .ah-query-item:hover {
            background: #1b3a4b;
        }
        
        .ah-query-item.selected {
            background: linear-gradient(90deg, #00d9ff20 0%, #1b3a4b 100%);
            border-left: 3px solid #00d9ff;
        }
        
        .ah-query-name {
            font-size: 14px;
            font-weight: 500;
            color: #e0e0e0;
            margin-bottom: 4px;
        }
        
        .ah-query-kvps {
            font-size: 11px;
            color: #64dfdf;
        }
        
        .ah-footer {
            padding: 15px 20px;
            border-top: 1px solid #2d4a5e;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }
        
        .ah-btn {
            padding: 10px 25px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        
        .ah-btn-submit {
            background: linear-gradient(135deg, #00d9ff 0%, #00a8cc 100%);
            color: #0d1b2a;
        }
        
        .ah-btn-submit:hover:not(:disabled) {
            background: linear-gradient(135deg, #33e1ff 0%, #00c4eb 100%);
            box-shadow: 0 0 20px rgba(0, 217, 255, 0.4);
        }
        
        .ah-btn-submit:disabled {
            background: #2d4a5e;
            color: #5a6a7a;
            cursor: not-allowed;
        }
        
        .ah-btn-cancel {
            background: transparent;
            border: 1px solid #5a6a7a;
            color: #e0e0e0;
        }
        
        .ah-btn-cancel:hover {
            border-color: #ff4757;
            color: #ff4757;
        }
        
        /* Custom scrollbar */
        .ah-results-container::-webkit-scrollbar {
            width: 8px;
        }
        
        .ah-results-container::-webkit-scrollbar-track {
            background: #0a1628;
        }
        
        .ah-results-container::-webkit-scrollbar-thumb {
            background: #2d4a5e;
            border-radius: 4px;
        }
        
        .ah-results-container::-webkit-scrollbar-thumb:hover {
            background: #3d5a6e;
        }
    `;

    // ==========================================================================
    // STATE MANAGEMENT
    // ==========================================================================
    
    let selectedQuery = null;
    let currentKvps = {};

    // ==========================================================================
    // UTILITY FUNCTIONS
    // ==========================================================================

    /**
     * Parses key=value pairs from text input
     * Handles case-insensitive key matching
     * @param {string} text - Input text with one KVP per line
     * @returns {Object} - Object with lowercase keys and their values
     */
    function parseKvps(text) {
        const kvps = {};
        const lines = text.split('\n');
        
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || !trimmed.includes('=')) continue;
            
            const eqIndex = trimmed.indexOf('=');
            const key = trimmed.substring(0, eqIndex).trim().toLowerCase();
            const value = trimmed.substring(eqIndex + 1).trim();
            
            if (key && value) {
                kvps[key] = value;
            }
        }
        
        return kvps;
    }

    /**
     * Filters queries based on provided KVPs
     * A query matches if all its required KVPs are present
     * @param {Object} kvps - Parsed KVPs object
     * @returns {Array} - Array of matching query objects
     */
    function filterQueries(kvps) {
        if (!QUERY_LIBRARY) return [];
        const kvpKeys = Object.keys(kvps);
        return QUERY_LIBRARY.filter(query => {
            if (query.requiredKvps.length === 0) return true;
            return query.requiredKvps.every(required => kvpKeys.includes(required.toLowerCase()));
        });
    }

    /**
     * Substitutes KVP values into query template
     * @param {string} template - Query template with {{key}} placeholders
     * @param {Object} kvps - Parsed KVPs object
     * @returns {string} - Query with substituted values
     */
    function substituteKvps(template, kvps) {
        let result = template;
        
        for (const [key, value] of Object.entries(kvps)) {
            const regex = new RegExp(`\\{\\{${key}\\}\\}`, 'gi');
            result = result.replace(regex, value);
        }
        
        return result;
    }

    /**
     * Encodes query string: UTF-16LE → gzip compress → base64 URL-safe
     * @param {string} query - KQL query string
     * @returns {Promise<string>} - Encoded query string
     */
    async function encodeQuery(query) {
        // Convert to UTF-16LE
        const utf16Bytes = new Uint8Array(query.length * 2);
        for (let i = 0; i < query.length; i++) {
            const charCode = query.charCodeAt(i);
            utf16Bytes[i * 2] = charCode & 0xFF;         // Low byte
            utf16Bytes[i * 2 + 1] = (charCode >> 8) & 0xFF;  // High byte
        }

        // Gzip compress using CompressionStream
        const stream = new Blob([utf16Bytes]).stream();
        const compressedStream = stream.pipeThrough(new CompressionStream('gzip'));
        const compressedBlob = await new Response(compressedStream).blob();
        const compressedBuffer = await compressedBlob.arrayBuffer();
        const compressedBytes = new Uint8Array(compressedBuffer);

        // Convert to base64 URL-safe
        let base64 = btoa(String.fromCharCode(...compressedBytes));
        // Make URL-safe: + → -, / → _, remove padding =
        base64 = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        return base64;
    }

    /**
     * Extracts tenant ID from current URL
     * @returns {string|null} - Tenant ID or null if not found
     */
    function getTenantId() {
        const url = new URL(window.location.href);
        return url.searchParams.get('tid');
    }

    /**
     * Builds the Advanced Hunting URL with encoded query
     * @param {string} encodedQuery - Base64 URL-safe encoded query
     * @param {string} tenantId - Microsoft tenant ID
     * @returns {string} - Complete Advanced Hunting URL
     */
    function buildUrl(encodedQuery, tenantId) {
        let url = 'https://security.microsoft.com/v2/advanced-hunting';
        const params = new URLSearchParams();
        
        if (tenantId) {
            params.set('tid', tenantId);
        }
        params.set('query', encodedQuery);
        params.set('timeRangeId', 'month');
        
        return `${url}?${params.toString()}`;
    }

    // ==========================================================================
    // UI COMPONENTS
    // ==========================================================================

    /**
     * Creates and injects the modal UI
     */
    function createModal() {
        // Inject styles
        const styleEl = document.createElement('style');
        styleEl.id = 'ah-styles';
        styleEl.textContent = STYLES;
        document.head.appendChild(styleEl);

        // Create modal
        const modal = document.createElement('div');
        modal.className = 'ah-modal';
        modal.id = 'ah-modal';
        modal.innerHTML = `
            <div class="ah-header" id="ah-header">
                <div class="ah-title">
                    <span class="ah-title-icon">🔍</span>
                    Advanced Hunter
                </div>
                <button class="ah-close-btn" id="ah-close">×</button>
            </div>
            <div class="ah-body">
                <div class="ah-section kvp-section">
                    <label class="ah-section-label">Key-Value Pairs (one per line)</label>
                    <textarea 
                        class="ah-kvp-input" 
                        id="ah-kvp-input"
                        placeholder="alertid=adec1ab2064045c6edc926592925ec1c2827f3f8a&#10;networkmessageid=ef25129a-5f94-49f4-e131-08de6b7b6952&#10;ipaddress=192.168.1.100&#10;hostname=WORKSTATION01"
                    ></textarea>
                </div>
                <div class="ah-section results-section">
                    <label class="ah-section-label">Matching Queries</label>
                    <div class="ah-results-container" id="ah-results">
                        <div class="ah-results-empty" id="ah-loading-queries">
                            Loading queries...
                        </div>
                    </div>
                </div>
            </div>
            <div class="ah-footer">
                <button class="ah-btn ah-btn-cancel" id="ah-cancel">Cancel</button>
                <button class="ah-btn ah-btn-submit" id="ah-submit" disabled>Submit</button>
            </div>
        `;

        document.body.appendChild(modal);

        // Initialize event handlers
        initEventHandlers();
    }

    /**
     * Updates the query results based on current KVPs
     */
    function updateResults() {
        const resultsContainer = document.getElementById('ah-results');
        if (!QUERY_LIBRARY) {
            resultsContainer.innerHTML = `<div class="ah-results-empty">Loading queries...</div>`;
            selectedQuery = null;
            updateSubmitButton();
            return;
        }
        const matchingQueries = filterQueries(currentKvps);
        if (matchingQueries.length === 0) {
            resultsContainer.innerHTML = `
                <div class="ah-results-empty">
                    No queries match the provided KVPs
                </div>
            `;
            selectedQuery = null;
            updateSubmitButton();
            return;
        }
        resultsContainer.innerHTML = matchingQueries.map((query, index) => `
            <div class="ah-query-item" data-index="${QUERY_LIBRARY.indexOf(query)}">
                <div class="ah-query-name">${query.name}</div>
                <div class="ah-query-kvps">Required: ${query.requiredKvps.length > 0 ? query.requiredKvps.join(', ') : 'None'}</div>
            </div>
        `).join('');
        // Add click handlers to query items
        resultsContainer.querySelectorAll('.ah-query-item').forEach(item => {
            item.addEventListener('click', () => {
                resultsContainer.querySelectorAll('.ah-query-item').forEach(i => i.classList.remove('selected'));
                item.classList.add('selected');
                selectedQuery = QUERY_LIBRARY[parseInt(item.dataset.index)];
                updateSubmitButton();
            });
        });
        selectedQuery = null;
        updateSubmitButton();
    }

    /**
     * Updates the submit button state
     */
    function updateSubmitButton() {
        const submitBtn = document.getElementById('ah-submit');
        submitBtn.disabled = !selectedQuery;
    }

    /**
     * Initializes all event handlers
     */
    function initEventHandlers() {
        const modal = document.getElementById('ah-modal');
        const header = document.getElementById('ah-header');
        const closeBtn = document.getElementById('ah-close');
        const cancelBtn = document.getElementById('ah-cancel');
        const submitBtn = document.getElementById('ah-submit');
        const kvpInput = document.getElementById('ah-kvp-input');

        // Close handlers
        closeBtn.addEventListener('click', closeModal);
        cancelBtn.addEventListener('click', closeModal);

        // KVP input handler - real-time filtering
        kvpInput.addEventListener('input', () => {
            currentKvps = parseKvps(kvpInput.value);
            updateResults();
        });

        // Submit handler
        submitBtn.addEventListener('click', handleSubmit);

        // Draggable functionality
        let isDragging = false;
        let dragOffsetX = 0;
        let dragOffsetY = 0;

        header.addEventListener('mousedown', (e) => {
            if (e.target === closeBtn) return;
            isDragging = true;
            const rect = modal.getBoundingClientRect();
            dragOffsetX = e.clientX - rect.left;
            dragOffsetY = e.clientY - rect.top;
            // Explicitly set width/height to preserve flex layout during drag
            modal.style.width = rect.width + 'px';
            modal.style.height = rect.height + 'px';
            modal.style.transform = 'none';
            modal.style.left = rect.left + 'px';
            modal.style.top = rect.top + 'px';
        });

        document.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            e.preventDefault();
            modal.style.left = (e.clientX - dragOffsetX) + 'px';
            modal.style.top = (e.clientY - dragOffsetY) + 'px';
        });

        document.addEventListener('mouseup', () => {
            isDragging = false;
        });

        // Keyboard shortcut: Escape to close
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeModal();
            }
        });
    }

    /**
     * Handles the submit button click
     */
    async function handleSubmit() {
        if (!selectedQuery) return;

        try {
            const submitBtn = document.getElementById('ah-submit');
            submitBtn.textContent = 'Processing...';
            submitBtn.disabled = true;

            // Substitute KVPs into query template
            const finalQuery = substituteKvps(selectedQuery.template, currentKvps);
            
            // Encode the query
            const encodedQuery = await encodeQuery(finalQuery);
            
            // Get tenant ID from current URL
            const tenantId = getTenantId();
            
            // Build the new URL
            const newUrl = buildUrl(encodedQuery, tenantId);
            
            // Navigate to the new URL
            window.location.href = newUrl;
        } catch (error) {
            console.error('Advanced Hunter Error:', error);
            alert('Error processing query: ' + error.message);
            const submitBtn = document.getElementById('ah-submit');
            submitBtn.textContent = 'Submit';
            submitBtn.disabled = false;
        }
    }

    /**
     * Closes and removes the modal
     */
    function closeModal() {
        const modal = document.getElementById('ah-modal');
        const styles = document.getElementById('ah-styles');
        
        if (modal) modal.remove();
        if (styles) styles.remove();
        
        selectedQuery = null;
        currentKvps = {};
    }

    // ==========================================================================
    // INITIALIZATION
    // ==========================================================================

    // Check if modal already exists (prevent double-load)
    if (document.getElementById('ah-modal')) {
        closeModal();
    }

    // Create the modal
    createModal();

    // Fetch the query library JSON
    fetch(QUERY_LIBRARY_URL)
        .then(response => {
            if (!response.ok) throw new Error('Failed to load query library');
            return response.json();
        })
        .then(data => {
            QUERY_LIBRARY = data;
            updateResults();
        })
        .catch(err => {
            QUERY_LIBRARY = [];
            const resultsContainer = document.getElementById('ah-results');
            if (resultsContainer) {
                resultsContainer.innerHTML = `<div class="ah-results-empty">Error loading queries.<br>${err.message}</div>`;
            }
        });

})();