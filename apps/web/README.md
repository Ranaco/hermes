# Hermes KMS - Web Application

A modern, industrial-grade frontend for the Hermes Key Management System built with Next.js 14, React Query, Zustand, and Shadcn/ui.

## 🚀 Features

- **Modern UI**: Funky, modern interface with custom Shadcn theme
- **State Management**: 
  - **React Query** for server state (API data fetching, caching, synchronization)
  - **Zustand** for client state (UI state, auth state)
- **Authentication**: Secure login/registration flow
- **Key Management**: Create, view, rotate, and delete encryption keys
- **Secret Management**: Securely store and manage secrets
- **Vault Operations**: Organize secrets in secure vaults
- **Responsive Design**: Mobile-first, fully responsive
- **Dark Mode**: Built-in theme switching
- **Type Safety**: Full TypeScript support

## 🎨 Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS v4
- **UI Components**: Shadcn/ui with custom theme
- **State Management**: 
  - React Query (TanStack Query) - Server state
  - Zustand - Client state
- **Forms**: React Hook Form + Zod validation
- **HTTP Client**: Axios with interceptors
- **Fonts**: DM Sans + Space Mono
- **Icons**: Lucide React

## 📦 Installation

```bash
# From the monorepo root
npm install

# Or from apps/web
cd apps/web
npm install
```

## 🔧 Configuration

Create a `.env.local` file in `apps/web`:

```env
NEXT_PUBLIC_API_URL=http://localhost:3000/api/v1
```

## 🏃 Development

```bash
# Run the web app only (on port 3001)
cd apps/web
npm run dev

# Or from monorepo root using turbo
npm run dev
```

Visit [http://localhost:3001](http://localhost:3001)

## 🏗️ Build

```bash
npm run build
npm run start
```

## 📁 Project Structure

```
apps/web/
├── src/
│   ├── app/                    # Next.js App Router pages
│   │   ├── dashboard/         # Dashboard pages
│   │   │   ├── keys/         # Key management
│   │   │   ├── secrets/      # Secret management
│   │   │   ├── vaults/       # Vault management
│   │   │   ├── users/        # User management
│   │   │   └── settings/     # Settings
│   │   ├── login/            # Auth pages
│   │   └── layout.tsx        # Root layout
│   ├── components/            # React components
│   │   ├── ui/               # Shadcn UI components
│   │   ├── dashboard-layout.tsx
│   │   └── providers.tsx     # App providers
│   ├── hooks/                 # Custom React hooks
│   │   ├── use-auth.ts       # Auth hooks
│   │   ├── use-keys.ts       # Key management hooks
│   │   ├── use-secrets.ts    # Secret management hooks
│   │   └── use-vaults.ts     # Vault management hooks
│   ├── services/              # API services
│   │   ├── auth.service.ts
│   │   ├── key.service.ts
│   │   ├── secret.service.ts
│   │   └── vault.service.ts
│   ├── store/                 # Zustand stores
│   │   ├── auth.store.ts     # Auth state
│   │   └── ui.store.ts       # UI state
│   └── lib/                   # Utilities
│       ├── api.ts            # Axios instance
│       └── utils.ts          # Helper functions
├── public/                    # Static assets
└── package.json
```

## 🎨 Custom Theme

The app uses a custom Shadcn theme with:
- **Primary**: Bold red (#FF3132)
- **Secondary**: Vibrant yellow (#FFFF0E)
- **Accent**: Electric blue (#0065FD)
- **Border Radius**: 0px (sharp edges)
- **Shadows**: Bold box shadows with offsets
- **Fonts**: DM Sans + Space Mono

## 🔐 Features by Page

### Dashboard
- Overview statistics
- Recent keys and vaults
- Activity metrics
- Quick access cards

### Keys Management
- List all encryption keys
- Create new keys (encryption, signing, HMAC)
- Rotate keys
- Delete keys
- Search and filter

### Secrets Management
- Store sensitive data
- Version control
- Show/hide secret values
- Search functionality

### Vaults
- Create secure storage containers
- Organize secrets by vault
- Status indicators
- Grid layout

### Settings
- Profile management
- Security settings
- Password change
- Notification preferences

## 🔌 API Integration

The app connects to the Hermes KMS API. Make sure the API is running on `http://localhost:3000` or update `NEXT_PUBLIC_API_URL` in `.env.local`.

### API Endpoints Used
- `POST /auth/login` - User authentication
- `POST /auth/register` - User registration
- `GET /keys` - List keys
- `POST /keys` - Create key
- `POST /keys/:id/rotate` - Rotate key
- `GET /secrets` - List secrets
- `POST /secrets` - Create secret
- `GET /vaults` - List vaults
- `POST /vaults` - Create vault

## 🧪 State Management

### React Query (Server State)
- Automatic caching and revalidation
- Background refetching
- Optimistic updates
- Query invalidation on mutations

### Zustand (Client State)
- Auth state (user, token, auth status)
- UI state (sidebar, theme)
- Persistent storage for auth

## 🎯 Best Practices

- ✅ Type-safe API calls
- ✅ Optimistic UI updates
- ✅ Error handling with toast notifications
- ✅ Responsive design
- ✅ Accessible components
- ✅ SEO optimized
- ✅ Performance optimized

## 📝 License

Part of the Hermes KMS monorepo.

