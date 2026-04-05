## Stage 1: AWS Config Parser
**Goal**: Read ~/.aws/config and extract SSO instances (start_url + region pairs)
**Status**: Complete

## Stage 2: SSO OIDC Authentication
**Goal**: Implement authorization_code + PKCE flow against AWS SSO OIDC
**Status**: Complete

## Stage 3: Token Cache (AWS CLI compatible)
**Goal**: Read/write SSO tokens in ~/.aws/sso/cache/ in AWS CLI format
**Status**: Complete

## Stage 4: Token Monitor & Renewal
**Goal**: Background goroutine that tracks expiry and refreshes tokens
**Status**: Complete

## Stage 5: macOS Menu Bar UI
**Goal**: Systray icon showing session state and remaining time
**Status**: Complete
