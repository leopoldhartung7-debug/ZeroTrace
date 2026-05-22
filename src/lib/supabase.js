import { createClient } from '@supabase/supabase-js'
import { SUPABASE_URL, SUPABASE_ANON_KEY, supabaseEnabled } from './supabaseConfig.js'

// Single shared client. Null when not configured so the app keeps working
// purely on local storage until you add your project credentials.
export const supabase = supabaseEnabled()
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: { persistSession: true, autoRefreshToken: true },
    })
  : null

export { supabaseEnabled }
