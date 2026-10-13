/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Which tab set this build ships — see src/shell/editions.ts. */
  readonly VITE_EDITION?: 'core' | 'full';
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
