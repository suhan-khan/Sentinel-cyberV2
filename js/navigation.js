/**
 * Sentinel Cyber — Navigation Controller
 * Handles sidebar toggling, active states, page routing, and mobile responsiveness.
 */
window.Navigation = {
  isMobileOpen: false,
  isCollapsed: false,

  init() {
    // 1. Navigation item clicks
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const pageId = item.getAttribute('data-page');
        if (pageId && window.SentinelApp) {
          window.SentinelApp.navigateTo(pageId);
          if (this.isMobileOpen) {
            this.closeMobileSidebar();
          }
        }
      });
    });

    // 2. Sidebar collapse toggle
    const toggleBtn = document.getElementById('sidebar-toggle');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        if (window.innerWidth <= 992) {
          this.toggleMobileSidebar();
        } else {
          this.toggleSidebar();
        }
      });
    }

    // 3. Mobile overlay click
    const mobileOverlay = document.getElementById('mobile-overlay');
    if (mobileOverlay) {
      mobileOverlay.addEventListener('click', () => {
        this.closeMobileSidebar();
      });
    }

    // 4. Window resize listener
    window.addEventListener('resize', () => {
      if (window.innerWidth > 992 && this.isMobileOpen) {
        this.closeMobileSidebar();
      }
    });

    // 5. Restore collapsed state
    const savedCollapse = localStorage.getItem('sentinel_sidebar_collapsed');
    if (savedCollapse === 'true' && window.innerWidth > 992) {
      this.collapseSidebar(true);
    }
  },

  setActive(pageId) {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      if (item.getAttribute('data-page') === pageId) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });
  },

  toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainWrapper = document.querySelector('.main-wrapper') || document.querySelector('.main-content');
    
    this.isCollapsed = !this.isCollapsed;
    sidebar.classList.toggle('collapsed', this.isCollapsed);
    if (mainWrapper) {
      mainWrapper.classList.toggle('sidebar-collapsed', this.isCollapsed);
    }
    localStorage.setItem('sentinel_sidebar_collapsed', this.isCollapsed);
  },

  collapseSidebar(collapsed) {
    const sidebar = document.getElementById('sidebar');
    const mainWrapper = document.querySelector('.main-wrapper') || document.querySelector('.main-content');
    this.isCollapsed = collapsed;
    sidebar.classList.toggle('collapsed', collapsed);
    if (mainWrapper) {
      mainWrapper.classList.toggle('sidebar-collapsed', collapsed);
    }
  },

  toggleMobileSidebar() {
    if (this.isMobileOpen) {
      this.closeMobileSidebar();
    } else {
      this.openMobileSidebar();
    }
  },

  openMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('mobile-overlay');
    sidebar.classList.add('mobile-open');
    if (overlay) overlay.classList.add('active');
    document.body.style.overflow = 'hidden';
    this.isMobileOpen = true;
  },

  closeMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('mobile-overlay');
    sidebar.classList.remove('mobile-open');
    if (overlay) overlay.classList.remove('active');
    document.body.style.overflow = '';
    this.isMobileOpen = false;
  }
};
