/**
 * CryptoLab - Operation History Controller
 * Search, filter, delete individual items, clear all, and CSV export.
 */

const HistoryPage = {
  currentFilterAlgo: 'all',
  currentFilterOp: 'all',
  searchQuery: '',

  init() {
    this.tableBody = document.getElementById('history-table-body');
    this.countBadge = document.getElementById('history-count-badge');
    this.filterAlgoSelect = document.getElementById('history-filter-algo');
    this.filterOpSelect = document.getElementById('history-filter-op');
    this.searchInput = document.getElementById('history-search');
    this.btnClearAll = document.getElementById('history-clear-all-btn');
    this.btnExportCSV = document.getElementById('history-export-csv-btn');

    if (!this.tableBody) return;

    // Event listeners
    if (this.filterAlgoSelect) {
      this.filterAlgoSelect.addEventListener('change', () => {
        this.currentFilterAlgo = this.filterAlgoSelect.value;
        this.render();
      });
    }

    if (this.filterOpSelect) {
      this.filterOpSelect.addEventListener('change', () => {
        this.currentFilterOp = this.filterOpSelect.value;
        this.render();
      });
    }

    if (this.searchInput) {
      this.searchInput.addEventListener('input', () => {
        this.searchQuery = this.searchInput.value.toLowerCase().trim();
        this.render();
      });
    }

    if (this.btnClearAll) {
      this.btnClearAll.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all operation history? This cannot be undone.')) {
          HistoryManager.clearAll();
          this.render();
          Toast.info('History Cleared', 'All stored cryptographic operations deleted.');
        }
      });
    }

    if (this.btnExportCSV) {
      this.btnExportCSV.addEventListener('click', () => {
        HistoryManager.exportCSV();
      });
    }

    window.addEventListener('cryptolab:history_updated', () => {
      this.render();
    });

    this.render();
  },

  formatTime(isoStr) {
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch (e) {
      return isoStr;
    }
  },

  getBadgeClass(algo) {
    if (['Caesar Cipher', 'Multiplicative Cipher', 'Hill Cipher'].includes(algo)) {
      return 'badge-classical';
    } else if (algo === 'SHA-256') {
      return 'badge-hash';
    } else if (algo.startsWith('HMAC')) {
      return 'badge-mac';
    }
    return 'badge-modern';
  },

  render() {
    if (!this.tableBody) return;
    const allEntries = HistoryManager.getAll();

    // Filter entries
    const filtered = allEntries.filter(item => {
      if (this.currentFilterAlgo !== 'all' && item.algorithm !== this.currentFilterAlgo) {
        return false;
      }
      if (this.currentFilterOp !== 'all' && item.operation !== this.currentFilterOp) {
        return false;
      }
      if (this.searchQuery) {
        const text = `${item.algorithm} ${item.operation} ${item.inputSnippet} ${item.outputSnippet} ${item.details}`.toLowerCase();
        if (!text.includes(this.searchQuery)) {
          return false;
        }
      }
      return true;
    });

    if (this.countBadge) {
      this.countBadge.textContent = `${filtered.length} record${filtered.length === 1 ? '' : 's'}`;
    }

    if (filtered.length === 0) {
      this.tableBody.innerHTML = `
        <tr>
          <td colspan="7" class="empty-state">
            <div class="empty-state-icon">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
            </div>
            <h4>No Operations Found</h4>
            <p style="margin-top: 0.25rem;">Perform an encryption, decryption, hash, or HMAC operation in the toolkits to record activity.</p>
          </td>
        </tr>
      `;
      return;
    }

    this.tableBody.innerHTML = filtered.map(item => `
      <tr>
        <td style="white-space: nowrap; color: var(--text-muted); font-size: 0.8rem;">
          ${this.formatTime(item.timestamp)}
        </td>
        <td>
          <span class="badge ${this.getBadgeClass(item.algorithm)}">
            ${item.algorithm}
          </span>
        </td>
        <td>
          <strong style="color: var(--primary); font-size: 0.85rem;">${item.operation}</strong>
        </td>
        <td style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          <code style="font-size: 0.8rem; background: var(--bg-page); padding: 2px 6px; border-radius: 4px;">${this.escapeHtml(item.inputSnippet || '—')}</code>
        </td>
        <td style="max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          <code style="font-size: 0.8rem; background: var(--bg-page); padding: 2px 6px; border-radius: 4px; color: var(--secondary);">${this.escapeHtml(item.outputSnippet || '—')}</code>
        </td>
        <td style="font-size: 0.8rem; color: var(--text-muted);">
          ${this.escapeHtml(item.details || '—')}
        </td>
        <td style="text-align: right; white-space: nowrap;">
          <button class="btn btn-outline btn-icon-only btn-sm history-delete-btn" data-id="${item.id}" title="Delete Record">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          </button>
        </td>
      </tr>
    `).join('');

    // Attach individual delete button events
    this.tableBody.querySelectorAll('.history-delete-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        HistoryManager.deleteById(id);
        Toast.info('Record Removed', 'Operation removed from history.');
      });
    });
  },

  escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
};

document.addEventListener('DOMContentLoaded', () => {
  HistoryPage.init();
});
