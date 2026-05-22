// Supabase connection — fill these with YOUR project values.
// Both are PUBLIC by design (the anon key is meant to live in the browser);
// real security comes from Row Level Security policies in the database.
//
// Find them in: Supabase dashboard → Project Settings → API
//   - Project URL          → SUPABASE_URL
//   - Project API keys: anon public → SUPABASE_ANON_KEY
//
// Leave them empty to keep the app running fully on local storage.
export const SUPABASE_URL = ''
export const SUPABASE_ANON_KEY = ''

export const supabaseEnabled = () => Boolean(SUPABASE_URL && SUPABASE_ANON_KEY)
