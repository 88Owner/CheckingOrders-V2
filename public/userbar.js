// Userbar functionality for navigation and user management
(function() {
    'use strict';

    // Check if user is logged in and show appropriate navigation
    async function checkUserStatus() {
        try {
            const token = sessionStorage.getItem('auth_token') || sessionStorage.getItem('checkerAuthToken');
            const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
            
            const response = await fetch('/api/me', { 
                headers, 
                credentials: 'include' 
            });
            const result = await response.json();
            
            if (result.success) {
                // User is logged in
                showUserInfo(result.username, result.role);
                return true;
            } else {
                // User is not logged in
                showGuestInfo();
                return false;
            }
        } catch (error) {
            console.error('Error checking user status:', error);
            showGuestInfo();
            return false;
        }
    }

    // Show user information and navigation
    function showUserInfo(username, role) {
        // Hide login button, show logout button
        const loginBtn = document.getElementById('loginBtn');
        const logoutBtn = document.getElementById('logoutBtn');
        
        if (loginBtn) loginBtn.style.display = 'none';
        if (logoutBtn) {
            logoutBtn.style.display = 'inline-block';
            logoutBtn.onclick = handleLogout;
        }

        // Show user info if element exists
        const userInfo = document.getElementById('userInfo');
        if (userInfo) {
            userInfo.innerHTML = `
                <span>Xin chào, <strong>${username}</strong> (${role})</span>
            `;
            userInfo.style.display = 'block';
        }

        // Show role-specific navigation
        showRoleNavigation(role);
    }

    // Show guest information
    function showGuestInfo() {
        const loginBtn = document.getElementById('loginBtn');
        const logoutBtn = document.getElementById('logoutBtn');
        
        if (loginBtn) loginBtn.style.display = 'inline-block';
        if (logoutBtn) logoutBtn.style.display = 'none';

        // Hide user info
        const userInfo = document.getElementById('userInfo');
        if (userInfo) {
            userInfo.style.display = 'none';
        }
    }

    // Show navigation based on user role
    function showRoleNavigation(role) {
        const navLinks = document.getElementById('navLinks');
        if (!navLinks) return;

        let links = '';

        switch (role) {
            case 'admin':
                links = `
                    <a href="/admin" class="nav-link">Quản trị</a>
                    <a href="/" class="nav-link">Trang chủ</a>
                `;
                break;
            case 'checker':
                links = `
                    <a href="/checker-home" class="nav-link">Trang chủ</a>
                    <a href="/check" class="nav-link">Kiểm tra đơn hàng</a>
                `;
                break;
            case 'packer':
                links = `
                    <a href="/dashboard" class="nav-link">Trang chủ</a>
                    <a href="/check" class="nav-link">Kiểm tra đơn hàng</a>
                `;
                break;
            default:
                links = `
                    <a href="/" class="nav-link">Trang chủ</a>
                `;
        }

        navLinks.innerHTML = links;
    }

    // Handle logout
    async function handleLogout() {
        if (confirm('Bạn có chắc chắn muốn đăng xuất?')) {
            try {
                const token = sessionStorage.getItem('auth_token') || sessionStorage.getItem('checkerAuthToken');
                const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
                
                await fetch('/api/logout', { 
                    method: 'POST', 
                    headers,
                    credentials: 'include' 
                });
                
                // Clear session storage
                sessionStorage.removeItem('auth_token');
                sessionStorage.removeItem('checkerAuthToken');
                sessionStorage.removeItem('previousPage');
                
                // Redirect to login page
                window.location.href = '/login';
            } catch (error) {
                console.error('Logout error:', error);
                // Still redirect even if logout fails
                window.location.href = '/login';
            }
        }
    }

    // Initialize when DOM is loaded
    document.addEventListener('DOMContentLoaded', function() {
        checkUserStatus();
    });

    // Make functions available globally
    window.checkUserStatus = checkUserStatus;
    window.handleLogout = handleLogout;

})();