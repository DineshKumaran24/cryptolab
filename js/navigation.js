/**
 * CryptoLab - Navigation Controller
 * Handles active links, breadcrumb trail, and tab switching
 */

const Navigation = {
  init() {
    this.highlightActivePage();
    this.setupTabNavs();
  },

  highlightActivePage() {
    const currentPath = window.location.pathname.split('/').pop() || 'index.html';

    // Highlight desktop navbar links
    document.querySelectorAll('.nav-link').forEach(link => {
      const href = link.getAttribute('href');
      if (href && (href === currentPath || (currentPath === '' && href === 'index.html'))) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Highlight sidebar links
    document.querySelectorAll('.sidebar-link').forEach(link => {
      const href = link.getAttribute('href');
      if (href && (href === currentPath || (currentPath === '' && href === 'index.html'))) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Highlight mobile drawer links
    document.querySelectorAll('.mobile-drawer-link').forEach(link => {
      const href = link.getAttribute('href');
      if (href && (href === currentPath || (currentPath === '' && href === 'index.html'))) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });
  },

  setupTabNavs() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-tab');
        if (!targetId) return;

        const parentNav = btn.closest('.tab-nav') || btn.closest('.algo-tabs-bar');
        const container = parentNav ? parentNav.parentElement : document;

        // Deactivate all sibling buttons
        parentNav.querySelectorAll('.tab-btn, .algo-tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        // Toggle corresponding panes
        container.querySelectorAll('.tab-pane').forEach(pane => {
          if (pane.id === targetId) {
            pane.classList.add('active');
          } else {
            pane.classList.remove('active');
          }
        });
      });
    });
  }
};

document.addEventListener('DOMContentLoaded', () => {
  Navigation.init();
});
