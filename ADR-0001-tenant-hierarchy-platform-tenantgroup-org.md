# ADR-0001: Hierarki tenant (tenant-group → organization) lewat grant per-tenant

- **Status:** Proposed — mekanisme **dikunci ke eager per-tenant provisioning (opsi b)**.
  Body pra-Phase-8b (re-stamp lintas scope) dihapus; lihat "Riwayat" di akhir.
  Menunggu review sebelum ada implementasi.
- **Tanggal:** 2026-10-30 (revisi mekanisme: 2026-10-30, setelah Phase 8b ditemukan saat rebase)
- **Pengambil keputusan:** Nanang (product), didiskusikan bersama Claude
- **Terkait:** `PHASE8-PLATFORM-ADMIN-SKETCH.md`, `PHASE8B-AUTHZ-TENANT-SKETCH.md` (TD-03),
  `tech-debt.md` TD-04, `tenant.Descriptor.ParentID` (reserved, sketch Phase7 §8 item 3),
  `espresso/tenantgate.go`, `espresso/decision.go`, `authz/store.go`, `authz/tenanttest`

## Ringkasan keputusan

Tiga level akses (platform admin / tenant-group admin / organization admin)
dibangun **di application layer, tanpa mengubah tamper core**. Seorang
tenant-group admin diperlakukan sebagai **guest** di setiap organisasi
anaknya: ia punya **binding nyata di scope tiap organisasi**, bukan satu
binding di scope grup yang "mengembang" saat query.

Ekspansi terjadi **saat provisioning** (grant/revoke, dan saat keanggotaan org
berubah), di dalam satu transaksi, dengan `RoleMap` fail-closed. Saat request,
tidak ada komposisi lintas scope: scope pertanyaan = organisasi, dan
`authz.RBAC` dipakai apa adanya.

Gagasan intinya sederhana dan sudah ada di tamper: **tenant-group admin = user
home tenant-group yang `EnterTenant` ke organisasi anak dan memegang satu
binding di sana.** Ini persis model platform admin Phase 8, satu tingkat lebih
dalam. Tidak ada konsep baru, tidak ada gate baru, tidak ada binding yang
melewati batas tenant.

## 1. Konteks produk

Kebutuhan:

1. **Platform admin** — akses seluruh platform, semua tenant-group & organisasi.
2. **Tenant-group admin** (reseller/distributor) — akses ke banyak organisasi anaknya.
3. **Organization admin** — akses ke satu organisasi.

Prinsip `CLAUDE.md` "tamper still names no table" tetap: hierarki ini urusan
app. `tenant.Descriptor.ParentID` tetap **RESERVED** di tamper — tidak
diresolve, tidak diwarisi, tidak dicabang. App yang membacanya lewat port
miliknya sendiri.

## 2. Konteks teknis yang mengikat (Phase 7 + 8 + 8b)

Ini bukan preferensi; ini batas keras yang sudah settled.

- **Phase 8b §3:** *"There is no binding that spans tenants. A 'global' binding
  (`Resource{Type, ""}`) is global inside its scope only. A platform admin who
  must work in ten tenants has a binding in each. That is the cost of decision
  2, and it is also what lets a customer list exactly who the guests are:
  `ListSubjects` returns subjects with their home tenant."*
- **Phase 8b §2.2:** *"A guest needs a binding in the tenant entered. The
  subject is (home tenant, type, id). Roles held at home never apply somewhere
  else."*
- **Phase 8b §5:** invariants — (1) *"A binding in one scope never answers a
  question in another."*; (2) *"A subject of one tenant never matches a binding
  granted to the same `{Type, ID}` of another tenant."*; (3) *"No error return
  is read as allow."*
- **Phase 8 §3:** *"`Event.TenantID` is the row's scope and `Actor.TenantID` is
  the actor's home tenant."* Satu token = satu tenant; masuk (`EnterTenant`)
  tidak menulis refresh session.
- **`espresso/decision.go`:** *"roles held at home are bindings of another scope
  and are never consulted."* `DecisionGate.Tenant` menetapkan **scope**;
  subjek memakai home tenant dari `htid`.
- **`authz/store.go`:** *"A binding returned has Tenant set to tenantID."*
- **`authz/tenanttest.RunBindingStoreLeakSuite`:** sebuah store yang
  mengembalikan binding dengan `Tenant` **bukan** scope yang ditanya gagal
  suite ini. (Suite ini menguji adapter, bukan wrapper, dan menyemai resource
  bertipe `"thing"` tanpa hierarchy — jadi ia **tidak** menangkap wrapper
  re-stamp yang mengarang baris ber-stempel scope anak. Alasan wrapper itu gugur
  ada di Alternatif D.)
- **`CLAUDE.md`:** standing rule 1 (tanpa compatibility code), 2 (deny-by-default),
  3 (cross-tenant miss 404, bukan 403), 4 (misconfig gagal di `New`), 6 (guard +
  test yang membuktikan guard menyala).

**Konsekuensi langsung:** mekanisme "re-stamp binding `tenant_group` menjadi
binding `organization`" (draft ADR ini sebelum revisi) **tidak valid secara
struktural** — ia melanggar §3/§5.1 di atas dan mengarang baris di scope yang
tidak menyimpannya. Itu dihapus, bukan ditambal.

## 3. Keputusan

### 3.1 Entitas dan scope

- **tenant-group** = `tenant.Descriptor` root (mis. `tg-acme`), tanpa parent.
- **organization** = `tenant.Descriptor` anak (mis. `org-1`, `ParentID:
  "tg-acme"`).
- Setiap pertanyaan otorisasi punya **satu scope**: tenant organisasi yang
  resource-nya disentuh. **Tenant-group tidak pernah menjadi scope route.**
  Ia adalah **home tenant** dari user-nya.
- **Platform admin** tetap murni Phase 8: user home tenant `platform` dengan
  membership + binding di tiap tenant yang dimasukinya. Tidak berubah di sini.

### 3.2 Model guest (mekanisme inti)

Seorang tenant-group admin adalah, untuk setiap organisasi anak:

```
user row        home tenant = tg-acme              (identity.Store)
keep/revoke     grant "admin tg-acme"              (app-owned, sumber niat)
binding         Tenant: org-1, Subject: {tg-acme, user, bob},
                Resource: {organization, org-1}, Role: org_admin
```

Saat request ke route organisasi:

1. `RequireTenantAllowEntered` menerima token `tid=org-1`, `htid=tg-acme`.
2. `DecisionGate.Tenant` menetapkan scope = `org-1`.
3. `DecisionGate` membangun subjek `{Tenant: htid=tg-acme, user, bob}`.
4. `authz.RBAC.Check(ctx, org-1, subject, act, res)` membaca binding di scope
   `org-1` — yang benar-benar ada.

Tidak ada OR lintas scope, tidak ada wrapper store, tidak ada binding yang
melewati batas tenant. Ini **persis** jalur platform admin Phase 8; yang
berbeda hanya cara grant-nya di-provision (§3.3).

### 3.3 Ekspansi saat provisioning, bukan saat query

`grant "admin tenant-group X"` adalah **operasi provisioning**, bukan sekadar
satu baris:

- menulis satu `Binding` nyata per organisasi anak X; membership `EnterTenant`
  **tidak** dimaterialisasi — ia dibaca dari intent + parentage saat `IsMember`
  dipanggil (lihat `TENANT-HIERARCHY-MANIFEST.md` 9b-1), sehingga tidak ada
  set turunan kedua yang bisa drift;
- di dalam **satu transaksi** bersama baris niat grant-nya (intent row, scope =
  grup — lihat paragraf di bawah);
- role ditranslasi lewat `RoleMap` (fail-closed): role grup yang tidak punya
  padanan org membuat **seluruh grant gagal** — nol baris ditulis, bukan
  diteruskan mentah dan bukan intent tanpa ekspansi (intent yatim akan
  dilaporkan guard selamanya);
- `revoke` menghapus seluruh baris turunannya dalam satu transaksi.

Perubahan keanggotaan organisasi juga memicu re-sync di transaksi yang sama:
org **ditambah** ke grup → perluas setiap grant grup yang ada; org **dipindah**
→ hapus baris di grup lama, tulis di grup baru; org **dihapus** → hapus barisnya.

**Intent row (scope = grup) adalah sumber kebenaran; baris per-organisasi
adalah proyeksi.** Grant "admin tenant-group X" disimpan sebagai satu baris
niat di scope X — `Resource{tenant_group, X}` — dan baris per-organisasi
diturunkan darinya. Guard rekonsiliasi (§3.7) membandingkan keduanya: binding
tanpa niat pendukung = *orphan*; niat tanpa binding di salah satu anaknya =
*missing*. Baris per-organisasi yang nyata inilah yang membuat
`ListSubjects(org-1)` mengembalikan group admin sebagai subjek nyata dengan
home tenant-nya (Phase 8b §3) — tanpa itu, group admin hanya terlihat di scope
grup dan access-review org under-report.

### 3.4 Batas scope — apa yang boleh dan tidak

- **DIPUTUSKAN:** otorisasi single-resource (`Check`, `CheckBulk`) **selalu**
  satu scope = organisasi. `ListResources`/`ListSubjects` juga satu scope =
  organisasi.
- **DIPUTUSKAN:** query di scope tenant-group **bukan** penentu otorisasi
  single-resource. Kalaupun app memakai "cek scope grup" untuk *navigasi*
  (menentukan grup mana yang boleh dijelajahi user), itu **read helper**, bukan
  PDP, dan tidak boleh menentukan boleh/tidaknya mutasi satu resource.
- **DILARANG:** meng-OR-kan hasil dua `Check` di scope berbeda untuk
  memutuskan satu resource. Itu membuat binding scope grup menjawab pertanyaan
  scope org — outcome yang Phase 8b §5.1 larang — dan membuka dua footgun:
  `ListSubjects` under-report, dan `a.Allowed || b.Allowed` yang menelan
  `err` (melanggar §5.3 / standing rule 2). Lihat Alternatif E.

### 3.5 Deny / miss

- Lapis tenant gate: `tid` tidak cocok dengan scope → **401** byte-identical
  dengan token invalid (mekanisme `RequireTenant`). Org tak dikenal, org root
  yang bukan milik subjek, dan grup lain semuanya 401; tidak ada oracle
  keberadaan.
- Lapis authz (sudah ter-pin ke scope org): org di grup subjek tapi tidak
  visible → **404** (`WriteNotVisible`); role terlihat tapi rank kurang → **403**
  (`WriteDenied`).
- Setiap `err` → **deny**, tidak pernah allow (Phase 8b §5.3).

### 3.6 Audit

Satu chain (keputusan M5). Untuk mutasi ber-scope organisasi:

- `Event.TenantID` = **organisasi** (scope baris);
- `Actor.TenantID` = **tenant-group** (home tenant, dari `htid`).

Level admin **tidak** dibedakan lewat `actor.subject_type` — `Subject.Type`
adalah `"user"` untuk semua level, dan `audit.ActorType` hanya punya
`user`/`service_account`/`system`. Level dibaca dari scope + role, bukan tipe
subjek.

### 3.7 Sync & rekonsiliasi (syarat keras, bukan opsional)

Ini yang membuat (b) aman. Menunda atau melewatkannya = kelas kegagalan senyap
yang `CLAUDE.md` larang.

1. **Satu jalur provisioning transaksional.** Tidak ada jalur lain yang
   menulis grant grup atau mengubah keanggotaan org. Grant tanpa ekspansinya,
   atau org baru tanpa re-sync, harus **tidak mungkin secara konstruksi**.
2. **Idempoten & tahan ulang.** Re-sync boleh dijalankan berkali-kali tanpa
   efek ganda (kunci unik per `(tenant, subject, resource)`).
3. **Reconciliation guard + test yang membuktikan guard menyala** (standing
   rule 6). Query rekonsiliasi: "untuk setiap grant grup G, setiap anak G
   harus punya baris binding yang sesuai." Guard dijalankan saat boot dan/atau
   CI, dan ada test dengan drift yang **sengaja** dibuat yang harus
   menggagalkannya. Guard tanpa test = guard yang bisa mati diam-diam
   (preseden Phase 0c).
4. **Indeks** pada `(tenant, subject, resource)` dan `(tenant, resource)` agar
   `Check`/`List*` tetap satu query murah.
5. **Bila C (jumlah anak per grup) tumbuh besar**, precompute ke tabel closure/
   denormalisasi — tetap semantik (b): baris nyata per organisasi. Jangan
   berpindah ke join query-time (itu kembali ke masalah re-stamp).

## 4. Alur

### 4.1 Struktur & siapa menyimpan apa

```
PLATFORM            bukan Descriptor; binding resource_type="system" (Phase 8)
      │
      ▼
TENANT-GROUP        tenant.Descriptor{ID:"tg-acme", ParentID:""}
 (home tenant)      grant niat app-owned "admin tg-acme"
      │  ParentID (dibaca APP lewat port sendiri; tamper tak menyentuhnya)
      ├──────────────┬──────────────┐
      ▼              ▼              ▼
   org-1          org-2          org-3        tenant.Descriptor{ParentID:"tg-acme"}
   binding:       binding:       binding:     {Tenant: <org>, Subject:{tg-acme,user,bob},
   Tenant org-1   Tenant org-2   Tenant org-3  Resource:{organization,<org>}, Role:org_admin}
```

### 4.2 Request tenant-group admin ke org-1

```
RequireAuth              verifikasi JWT (tid=org-1, htid=tg-acme)
      │
      ▼
RequireTenantAllowEntered(tid harus == scope route)
      │
      ▼
DecisionGate{Tenant: TenantFromRoutedContext}   scope = org-1
      │   subject = {Tenant: htid=tg-acme, user, bob}
      ▼
authz.RBAC.Check(org-1, subject, "org:manage", {organization, org-1})
      │   binding di scope org-1 benar-benar ada (ditulis saat provisioning)
      ▼
Allowed / 404 / 403 — tanpa komposisi lintas scope
```

### 4.3 Provisioning & re-sync

```
grant  "admin tg-acme"  ──BEGIN──▶ RoleMap(role grup) ─▶ insert binding per anak (org-1..N)
org    ditambah ke grup ──BEGIN──▶ perluas setiap grant grup yang ada
org    dipindah         ──BEGIN──▶ hapus di grup lama, tulis di grup baru
org    dihapus          ──BEGIN──▶ hapus binding-nya
revoke "admin tg-acme"  ──BEGIN──▶ hapus binding turunannya
                                        │
                                        ▼
                        reconciliation guard (boot/CI) + test drift
```

## 5. Alternatif yang ditolak

### A. Resolve `ParentID` di tamper core
**Ditolak.** Melanggar invariant Phase 7 yang eksplisit ("Nothing in tamper
resolves it, inherits through it, or branches on it") dan
`TestMemStore_ParentIDCarriedNotResolved`. Butuh amend sketch Phase 7 dulu.

### B. `RequireTenant` menerima banyak tenant sekaligus
**Ditolak.** Menghilangkan properti 1-token-1-tenant; Phase 8 §3 menguncinya.

### C. Platform admin sebagai row `tenant.Descriptor`
**Ditolak.** Platform admin bukan tenant; memaksanya jadi row membuka case
khusus di gate.

### D. Re-stamp lintas scope (draft pra-revisi)
**Ditolak secara struktural**, karena tiga hal sekaligus: (1) `authz/store.go`
mewajibkan binding yang dikembalikan ber-`Tenant` sama dengan scope yang
ditanya; (2) `authz/rbac.go` membuang binding scope salah di `effective`,
`ListResources`, dan `ListSubjects`; (3) kalau wrapper menuliskan `Tenant =
scope anak` untuk lolos (1) dan (2), ia **mengarang baris tanpa backing
write** — `ListSubjects`/access-review dan guard drift pasti salah, dan tidak
ada baris nyata yang bisa direkonsiliasi. Leak suite **tidak** menangkap kasus
(3) karena ia menguji adapter dengan resource bertipe `"thing"` tanpa
hierarchy; jangan mengandalkannya sebagai bukti. Ini melanggar inti Phase 8b
§3/§5.1.

### E. Dua scoped-check di-OR di app layer (opsi a)
**Ditolak sebagai penentu otorisasi.** Secara mekanik tiap `Check` satu scope,
tapi hasil OR-nya membuat binding scope grup menentukan jawaban scope org —
outcome yang Phase 8b §5.1 larang. Dua biaya korektnes: `ListSubjects` satu
scope sehingga access-review organisasi **tidak** menampilkan group admin
(Phase 8b §3 menjanjikan sebaliknya), dan `a.Allowed || b.Allowed` menelan
`err` (melanggar §5.3). **Diizinkan hanya sebagai read helper navigasi** di
luar PDP, dengan kewajiban `err→deny` dan tanpa hak memutuskan mutasi
single-resource.

## 6. Konsekuensi

**Positif**
- tamper core 0 baris diubah; `authz.RBAC` dan `espresso.DecisionGate` dipakai
  apa adanya, tanpa wrapper store dan tanpa gate baru.
- Memakai kembali jalur platform admin yang sudah settled (`EnterTenant` +
  `RequireTenantAllowEntered` + binding per tenant); tidak menginvent konsep.
- `ListSubjects`/access-review tetap benar: group admin muncul sebagai subjek
  nyata di scope org, dengan home tenant-nya.
- Tidak ada oracle lintas grup; deny/miss tetap 401/404 sesuai standing rule 3.
- Satu binding = satu scope; leak suite tetap hijau tanpa pengecualian.

**Negatif / biaya yang diterima**
- **Amplifikasi tulis** O(C×A): grant/revoke dan setiap penambahan org menyentuh
  banyak baris. Ini cost yang Phase 8 sudah terima untuk platform admin.
- **Risiko drift senyap** bila ada jalur mutasi yang melewatkan re-sync —
  karena itu §3.7 syarat keras (satu jalur, guard, test).
- Ukuran tabel binding tumbuh dengan (jumlah grup × admin × anak). Perlu indeks
  dan, pada skala besar, closure/precompute.
- **Tidak menyelesaikan sumbu lain TD-04** (IdP, entitlement, domain): (b)
  tidak bisa "mem-provision" registry IdP. Lihat §8.

**Mitigasi**
- Satu jalur provisioning transaksional + rekonsiliasi idempoten (§3.7).
- Guard rekonsiliasi di boot/CI + test drift yang harus menggagalkannya.
- `RoleMap` fail-closed diuji: role grup tanpa mapping tidak mengembang.
- Cross-tenant-group leak suite (per-resource dan reverse-query) wajib ada
  sebelum merge.

## 7. Invariant (dasar test)

1. Sebuah binding hanya menjawab pertanyaan di scope-nya sendiri. Group admin
   mengakses org anak **melalui binding di scope org itu**, bukan lewat scope
   grup.
2. Subjek dari satu tenant tidak pernah cocok dengan binding untuk
   `{Type, ID}` yang sama di tenant lain.
3. Tidak ada error yang dibaca sebagai allow.
4. Misconfiguration (RoleMap kosong, resolusi parent gagal, scope tak valid)
   gagal di `New`/boot, bukan sebagai deny per-request yang menyamar sebagai
   traffic biasa.
5. Grant grup tanpa ekspansi, dan org baru tanpa re-sync, tidak mungkin
   secara konstruksi; guard rekonsiliasi menyala di CI/boot dan punya test
   yang membuktikan ia menyala.
6. `ListSubjects(org)` menampilkan setiap group admin yang punya akses ke org
   itu, dengan home tenant-nya.

## 8. Yang tidak diputuskan di sini

- **Sumbu IdP / entitlement / domain.** TD-04 menegaskan tiap sumbu diputuskan
  terpisah ("Decide inheritance for each axis separately"). Keputusan ini
  hanya untuk **roles** (`authz`). Pertanyaan produk di sketch Phase 7 §8 item 3
  ("apakah IdP parent melayani anak?") tetap terbuka.
- **Mekanisme re-sync konkret** (event, outbox, job) — keputusan implementasi,
  bukan ADR.
- **`MembershipsFor(userID)` tanpa home tenant.** Port identitas hanya menerima
  `userID`, tetapi `identity.Store.UserByID` juga me-resolve per id tanpa
  tenant — deployment sudah mengasumsikan id user unik global. Diselesaikan di
  manifest (keputusan 4): membership di-key `(userID, target)`; id yang
  bertabrakan antar-tenant adalah batasan yang didokumentasikan, bukan
  perubahan port.
- **Lifecycle tenant** (TD-05), **suspensi** (TD-06), **impersonasi** (TD-07).

## 9. Kapan ditinjau ulang

- Jika C (anak per grup) dan A (admin per grup) tumbuh sampai provisioning/
  rekonsiliasi jadi bottleneck → pertimbangkan closure table ter-precompute
  (masih semantik (b)).
- Jika jumlah level > 3 (reseller-of-reseller) → ekspansi jadi rekursif; tinjau
  ulang apakah tamper core perlu amend sketch Phase 7 §8 item 3.
- Jika product memutuskan access-review organisasi tidak perlu menampilkan
  group admin → (a) sebagai read helper bisa dipertimbangkan ulang, dengan
  syarat §3.4 dan `err→deny` tetap berlaku.

## Riwayat

- **2026-10-30 (draf awal, pra-Phase-8b):** mekanisme re-stamp binding
  `tenant_group` → `organization` lewat wrapper `BindingStore` (ADR §4a),
  mengasumsikan `authz.BindingStore` tidak tenant-aware.
- **2026-10-30 sore (blocking):** saat rebase ke `origin/main`, ketemu Phase 8
  (`MembershipStore`, `EnterTenant`, `htid`) dan Phase 8b (authz tenant-scoped,
  *"no binding that spans tenants"*) — diputuskan 2026-10-05, setelah draf
  ditulis. Build draft pecah 7 error; mekanisme §4a gugur secara struktural.
- **2026-10-30 (revisi ini):** mekanisme dikunci ke **eager per-tenant
  provisioning (opsi b)**. §4a dan diagram re-stamp dihapus. Opsi (a) ditolak
  sebagai penentu otorisasi, diizinkan hanya sebagai read helper. Batas scope,
  model guest, syarat sync/rekonsiliasi ditulis di §3.
