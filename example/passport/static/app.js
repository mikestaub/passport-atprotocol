async function main() {
  const statusElement = document.getElementById('status');
  const actionsElement = document.getElementById('actions');
  const outputElement = document.getElementById('output');

  async function fetchProfile() {
    try {
      const response = await fetch('/api/profile');
      if (response.ok) {
        const profile = await response.json();
        outputElement.textContent = JSON.stringify(profile, null, 2);
        return profile;
      } else {
        return null;
      }
    } catch (error) {
      if (error) {
        console.error('Error fetching profile:', error);
        outputElement.textContent = 'Error fetching profile';
      }
      return null;
    }
  }

  async function updateUI(profile) {
    actionsElement.innerHTML = '';
    if (profile) {
      statusElement.textContent = `Logged in as ${profile.handle}`;
      const logoutButton = document.createElement('button');
      logoutButton.textContent = 'Logout';
      logoutButton.onclick = () => (window.location.href = '/auth/atprotocol/logout');
      actionsElement.appendChild(logoutButton);

      const revokeButton = document.createElement('button');
      revokeButton.textContent = 'Revoke App Access';
      revokeButton.onclick = () => (window.location.href = '/auth/atprotocol/revoke');
      actionsElement.appendChild(revokeButton);
    } else {
      statusElement.textContent = 'Not logged in';
      const loginButton = document.createElement('button');
      loginButton.textContent = 'Login with ATProtocol';
      loginButton.onclick = () => (window.location.href = '/auth/atprotocol/login');
      actionsElement.appendChild(loginButton);
    }
  }

  const profile = await fetchProfile();
  await updateUI(profile);
}

document.addEventListener('DOMContentLoaded', main);
