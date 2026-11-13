/**
 * CryptoLab - Core Application Utilities
 * Shared state, Toast notifications, Clipboard helper, and LocalStorage History
 */

// Toast Notification System
const Toast = {
  container: null,

  init() {
    if (!this.container) {
      this.container = document.getElementById('toast-container');
      if (!this.container) {
        this.container = document.createElement('div');
        this.container.id = 'toast-container';
        document.body.appendChild(this.container);
      }
    }
  },

  show(title, message, type = 'info', duration = 3500) {
    this.init();
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    } else if (type === 'error') {
      iconSvg = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    } else if (type === 'warning') {
      iconSvg = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
    } else {
      iconSvg = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }

    toast.innerHTML = `
      <div class="toast-icon">${iconSvg}</div>
      <div class="toast-content">
        <div class="toast-title">${title}</div>
        <div class="toast-msg">${message}</div>
      </div>
      <button class="toast-close" title="Dismiss">&times;</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => {
      toast.remove();
    });

    this.container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  },

  success(title, message) { this.show(title, message, 'success'); },
  error(title, message) { this.show(title, message, 'error', 4500); },
  info(title, message) { this.show(title, message, 'info'); },
  warning(title, message) { this.show(title, message, 'warning', 4000); }
};

// Clipboard Helper with Fallback and Button Animation
const Clipboard = {
  async copy(text, buttonElement = null) {
    if (!text || text.trim() === '') {
      Toast.warning('Clipboard', 'No text available to copy.');
      return false;
    }

    let success = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        success = true;
      } else {
        // Fallback for non-https or older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        success = document.execCommand('copy');
        textArea.remove();
      }
    } catch (err) {
      console.warn('Clipboard write error:', err);
      success = false;
    }

    if (success) {
      Toast.success('Copied', 'Output copied to clipboard.');
      if (buttonElement) {
        const originalHtml = buttonElement.innerHTML;
        buttonElement.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!
        `;
        buttonElement.classList.add('btn-success');
        setTimeout(() => {
          buttonElement.innerHTML = originalHtml;
          buttonElement.classList.remove('btn-success');
        }, 1800);
      }
      return true;
    } else {
      Toast.error('Copy Failed', 'Unable to copy automatically. Please copy manually.');
      return false;
    }
  }
};

// History Manager with LocalStorage & Security Sanitization
const HistoryManager = {
  STORAGE_KEY: 'cryptolab_operation_history',

  getAll() {
    try {
      const data = localStorage.getItem(this.STORAGE_KEY);
      return data ? JSON.parse(data) : [];
    } catch (e) {
      console.error('LocalStorage read error:', e);
      return [];
    }
  },

  /**
   * Save an operation entry safely.
   * STRICT SECURITY REQUIREMENT: Never store private RSA keys, secret AES keys, or HMAC keys.
   */
  addEntry({ algorithm, operation, inputSnippet, outputSnippet, status = 'success', details = '' }) {
    try {
      const history = this.getAll();
      const newEntry = {
        id: 'op_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
        algorithm,
        operation, // 'Encryption', 'Decryption', 'Hash', 'HMAC Sign', 'HMAC Verify'
        inputSnippet: this.sanitizeSnippet(inputSnippet),
        outputSnippet: this.sanitizeSnippet(outputSnippet),
        status,
        timestamp: new Date().toISOString(),
        details: typeof details === 'string' ? details : JSON.stringify(details)
      };

      // Keep latest 100 entries
      history.unshift(newEntry);
      if (history.length > 100) {
        history.pop();
      }

      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(history));
      window.dispatchEvent(new CustomEvent('cryptolab:history_updated', { detail: newEntry }));
      return newEntry;
    } catch (e) {
      console.error('LocalStorage write error:', e);
      return null;
    }
  },

  sanitizeSnippet(str) {
    if (!str) return '';
    // Truncate long snippets for preview, strip possible private key headers
    let clean = String(str).trim();
    if (clean.includes('PRIVATE KEY')) {
      return '[REDACTED PRIVATE KEY]';
    }
    if (clean.length > 120) {
      return clean.substring(0, 117) + '...';
    }
    return clean;
  },

  deleteById(id) {
    try {
      let history = this.getAll();
      history = history.filter(item => item.id !== id);
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(history));
      window.dispatchEvent(new CustomEvent('cryptolab:history_updated'));
      return true;
    } catch (e) {
      console.error('Error deleting history entry:', e);
      return false;
    }
  },

  clearAll() {
    try {
      localStorage.removeItem(this.STORAGE_KEY);
      window.dispatchEvent(new CustomEvent('cryptolab:history_updated'));
      return true;
    } catch (e) {
      console.error('Error clearing history:', e);
      return false;
    }
  },

  getStats() {
    const history = this.getAll();
    const classicalCount = history.filter(h => ['Caesar Cipher', 'Multiplicative Cipher', 'Hill Cipher'].includes(h.algorithm)).length;
    const modernCount = history.filter(h => ['AES-GCM', 'RSA-OAEP', 'SHA-256', 'HMAC-SHA256'].includes(h.algorithm)).length;
    
    // Top algorithm used
    const algoFrequency = {};
    history.forEach(h => {
      algoFrequency[h.algorithm] = (algoFrequency[h.algorithm] || 0) + 1;
    });
    let topAlgo = 'None yet';
    let maxFreq = 0;
    for (const algo in algoFrequency) {
      if (algoFrequency[algo] > maxFreq) {
        maxFreq = algoFrequency[algo];
        topAlgo = algo;
      }
    }

    return {
      totalOperations: history.length,
      classicalOperations: classicalCount,
      modernOperations: modernCount,
      topAlgorithm: topAlgo,
      recent: history.slice(0, 6)
    };
  },

  exportCSV() {
    const history = this.getAll();
    if (!history || history.length === 0) {
      Toast.warning('Export CSV', 'No history records found to export.');
      return false;
    }

    const headers = ['ID', 'Timestamp (ISO)', 'Algorithm', 'Operation', 'Status', 'Input Preview', 'Output Preview', 'Details'];
    const rows = history.map(item => [
      `"${item.id}"`,
      `"${item.timestamp}"`,
      `"${item.algorithm.replace(/"/g, '""')}"`,
      `"${item.operation.replace(/"/g, '""')}"`,
      `"${item.status}"`,
      `"${(item.inputSnippet || '').replace(/"/g, '""')}"`,
      `"${(item.outputSnippet || '').replace(/"/g, '""')}"`,
      `"${(item.details || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `cryptolab_history_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    Toast.success('Export Successful', 'History downloaded as CSV file.');
    return true;
  }
};

// Global Mobile Navigation & Header Setup
document.addEventListener('DOMContentLoaded', () => {
  // Mobile drawer toggle
  const mobileToggle = document.querySelector('.nav-mobile-toggle');
  const drawer = document.querySelector('.mobile-drawer');
  const overlay = document.querySelector('.mobile-drawer-overlay');
  const drawerClose = document.querySelector('.mobile-drawer-close');

  if (mobileToggle && drawer && overlay) {
    const openDrawer = () => {
      drawer.classList.add('open');
      overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
    };

    const closeDrawer = () => {
      drawer.classList.remove('open');
      overlay.classList.remove('open');
      document.body.style.overflow = '';
    };

    mobileToggle.addEventListener('click', openDrawer);
    if (drawerClose) drawerClose.addEventListener('click', closeDrawer);
    overlay.addEventListener('click', closeDrawer);
  }
});
