# WIP: CTFd OAuth2 Plugin

An OAuth2 authentication plugin for CTFd that allows users to authenticate using external OAuth2 providers like Google, GitHub, AWS Cognito, and more.

## Features

- **Multiple OAuth2 Providers**: Support for any OAuth2-compliant provider
- **Dynamic Configuration**: Add/remove providers through the admin interface
- **Database Storage**: OAuth2 client configurations stored in database
- **Authlib**: Uses Authlib for standardized and secure defaults for OAuth2 handling

##
TODO: Add the option to configure flows using Authorization Code with PKCE so client secrets are not needed anymore

## Installation

1. Clone or download this plugin to your CTFd plugins directory:
   ```bash
   cd /path/to/CTFd/plugins
   git clone <repository-url> oauth2
   ```

2. Install required dependencies:
   ```bash
   pip install authlib
   ```

3. Restart CTFd to load the plugin

4. Navigate to Admin → Oauth2 Plugin to configure providers

## Configuration

### Adding an OAuth2 Provider
1. Go to **Admin Panel** → **Oauth2 Plugin**
2. Click **Add New Client**
3. Fill in the required fields:
   - **Provider Name**: Display name (e.g., "Google", "GitHub")
   - **Client ID**: OAuth2 Client ID from your provider
   - **Client Secret**: OAuth2 Client Secret from your provider
   - **Authorization URL**: Provider's authorization endpooint