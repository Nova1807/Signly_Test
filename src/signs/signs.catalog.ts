export interface SignCatalogEntry {
  id: string;
  name: string;
  glbUrl: string;
  category?: string;
}

export const SIGN_CATALOG: SignCatalogEntry[] = [
  {
    id: 'example-baum',
    name: 'Baum',
    glbUrl: 'https://storage.googleapis.com/dein-bucket/signs/baum.glb',
    category: 'Natur',
  },
];
