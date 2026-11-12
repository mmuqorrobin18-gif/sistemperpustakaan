// Edge Function "admin-users": Admin menambah, mengubah, mereset kata sandi,
// dan menghapus akun petugas. Memakai kunci service role yang tersedia otomatis
// di Supabase, jadi kunci itu tidak pernah sampai ke browser.
import { createClient } from 'npm:@supabase/supabase-js@2'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, 'Content-Type': 'application/json' } })

const ROLES = ['kepala', 'staf', 'duta']
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  try {
    const url = Deno.env.get('SUPABASE_URL')!
    const anon = Deno.env.get('SUPABASE_ANON_KEY')!
    const svc = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

    // 1. Pastikan pemanggil sudah masuk dan berperan Admin.
    const caller = createClient(url, anon, {
      global: { headers: { Authorization: req.headers.get('Authorization') ?? '' } },
    })
    const { data: who, error: whoErr } = await caller.auth.getUser()
    if (whoErr || !who?.user) return json({ error: 'Sesi tidak valid. Silakan masuk lagi.' }, 401)

    const admin = createClient(url, svc, { auth: { persistSession: false } })
    const { data: me } = await admin.from('profiles').select('role').eq('id', who.user.id).maybeSingle()
    if (me?.role !== 'admin') return json({ error: 'Hanya Admin yang boleh mengelola akun.' }, 403)

    const b = await req.json()
    const action = String(b.action ?? '')

    // 2. Tambah akun.
    if (action === 'create') {
      const email = String(b.email ?? '').trim().toLowerCase()
      const password = String(b.password ?? '')
      const nama = String(b.nama ?? '').trim()
      const role = String(b.role ?? '')
      if (!EMAIL.test(email)) return json({ error: 'Format email tidak valid.' }, 400)
      if (password.length < 6) return json({ error: 'Kata sandi minimal 6 karakter.' }, 400)
      if (!nama) return json({ error: 'Nama wajib diisi.' }, 400)
      if (!ROLES.includes(role)) return json({ error: 'Jabatan tidak valid.' }, 400)
      const { data: created, error: ce } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
      })
      if (ce || !created?.user) return json({ error: ce?.message ?? 'Gagal membuat akun.' }, 400)
      const { error: pe } = await admin.from('profiles').insert({ id: created.user.id, nama, role, email })
      if (pe) {
        await admin.auth.admin.deleteUser(created.user.id)
        return json({ error: pe.message }, 400)
      }
      return json({ ok: true, id: created.user.id })
    }

    // 3. Ubah atau hapus akun yang sudah ada (bukan Admin).
    const id = String(b.id ?? '')
    if (!id) return json({ error: 'ID akun wajib diisi.' }, 400)
    const { data: target } = await admin.from('profiles').select('id, role').eq('id', id).maybeSingle()
    if (!target) return json({ error: 'Akun tidak ditemukan.' }, 404)
    if (target.role === 'admin') return json({ error: 'Akun Admin tidak bisa diubah lewat sini.' }, 403)

    if (action === 'update') {
      const patch: Record<string, string> = {}
      const authPatch: Record<string, unknown> = {}
      if (b.nama !== undefined) {
        const nama = String(b.nama).trim()
        if (!nama) return json({ error: 'Nama wajib diisi.' }, 400)
        patch.nama = nama
      }
      if (b.role !== undefined) {
        if (!ROLES.includes(String(b.role))) return json({ error: 'Jabatan tidak valid.' }, 400)
        patch.role = String(b.role)
      }
      if (b.email !== undefined) {
        const email = String(b.email).trim().toLowerCase()
        if (!EMAIL.test(email)) return json({ error: 'Format email tidak valid.' }, 400)
        patch.email = email
        authPatch.email = email
        authPatch.email_confirm = true
      }
      if (b.password !== undefined && String(b.password) !== '') {
        if (String(b.password).length < 6) return json({ error: 'Kata sandi minimal 6 karakter.' }, 400)
        authPatch.password = String(b.password)
      }
      if (Object.keys(authPatch).length) {
        const { error: ue } = await admin.auth.admin.updateUserById(id, authPatch)
        if (ue) return json({ error: ue.message }, 400)
      }
      if (Object.keys(patch).length) {
        const { error: pe } = await admin.from('profiles').update(patch).eq('id', id)
        if (pe) return json({ error: pe.message }, 400)
      }
      return json({ ok: true })
    }

    if (action === 'delete') {
      if (id === who.user.id) return json({ error: 'Akun Anda sendiri tidak bisa dihapus.' }, 400)
      const { error: de } = await admin.auth.admin.deleteUser(id)
      if (de) return json({ error: de.message }, 400)
      return json({ ok: true })
    }

    return json({ error: 'Aksi tidak dikenal.' }, 400)
  } catch (e) {
    return json({ error: (e as Error).message ?? 'Terjadi kesalahan.' }, 500)
  }
})
