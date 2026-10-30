# ADR-0001: Hierarki tenant 3-tingkat (platform → tenant-group → organization) di atas tamper, lewat espresso

- **Status:** Proposed (direvisi setelah review — pin level + disiplin deny dua lapis dikoreksi; lihat §2 dan §6)
- **Tanggal:** 2026-10-30 (revisi: 2026-10-31)
- **Pengambil keputusan:** Nanang (product), didiskusikan bersama Claude
- **Terkait:** `tenant.Descriptor.ParentID` (reserved, sketch Phase7 §8 item 3), `PHASE7-MULTITENANCY-SKETCH.md`, `PHASE5-CUSTOM-ROLE-RBAC-SKETCH.md`, `espresso/tenantgate.go`, `espresso/decision.go`, implementasi referensi `examples/tenanthierarchy/`

## Konteks

tamper (Phase 7) sudah pooled multi-tenant — satu process serve N tenant lewat
`tenant.Descriptor{ID, Slug, ParentID, Status}`. `ParentID` ADA di struct tapi
**sengaja RESERVED**: tidak ada resolusi, tidak ada inheritance, tidak ada logic
apa pun yang membaca field itu di dalam tamper. Alasan tertulis di sketch §8
item 3: "whether a parent's IdP serves a child tenant is a real product
question... deliberately deferred — but the field exists so the answer can be
additive when it comes."

Kebutuhan produk sekarang: tiga level akses —

1. **Platform admin** — akses ke seluruh platform, semua tenant-group, semua organisasi.
2. **Tenant-group admin** (reseller/distributor) — akses ke BANYAK organisasi yang jadi anaknya.
3. **Organization admin** — akses ke SATU organisasi (level yang tamper sudah native-support lewat `authz.Resource{Type:"organization", ID:...}`).

tamper tidak punya konsep platform-admin atau tenant-group sebagai entitas
authz. Prinsip "tamper names no table" (CLAUDE.md) berarti hierarki 3-tingkat
ini WAJIB dibangun di layer aplikasi/consumer — bukan di-patch ke dalam tamper
core. Kita punya router house sendiri, **espresso**, dan tamper sudah
menyediakan adapter `tamper/espresso` (`RequireAuth`, `RequireTenant`/
`PinTenant`, `RequireDecision`/`DecisionGate`, `Auditor`) — jadi pertanyaan
sebenarnya bukan "apakah tamper bisa", tapi "gimana compose primitif yang
sudah ada di `tamper/espresso` + custom resolver app, tanpa menyentuh core
tamper atau melanggar invariant Phase 7 (404-never-403, deny-by-default,
tenant resolution ≠ authorization)".

Kendala yang membuat ini tidak trivial:

- `RequireTenant` (tamper/espresso) mem-pin SATU tenant per request dan
  cross-check `claims.TenantID == routed`. Ini didesain untuk 1 layer tenant
  flat — tidak tahu apa-apa soal "organisasi mana saja yang ada di bawah
  tenant-group ini".
- `authz.Authorizer.Check(sub, act, res)` butuh `Resource{Type, ID}` KONKRET.
  Tenant-group admin yang mau akses org-1..org-N tidak bisa dijawab oleh satu
  `Check` call — harus di-expand DULU ke daftar org konkret, atau binding-nya
  di-resolve lewat `ListResources` (unbounded flag).
- Platform admin lewat HTTP bukan hal yang otomatis "benar" — perlu keputusan
  eksplisit (lihat Alternatif B) karena ini permukaan risiko baru.

## Keputusan

Kami memutuskan: **bangun hierarki 3-tingkat sepenuhnya di application layer,
sebagai custom `BindingStore`/`PermissionStore` + resolver di atas
`tamper/authz` dan `tamper/espresso` — tamper core (`tenant`, `authz`, `audit`)
TIDAK diubah sama sekali.** `ParentID` dipakai sebagai carrier data mentah,
tetap tidak diresolve oleh tamper.

Implementasi referensi ada di `examples/tenanthierarchy/` (`bindingstore.go`,
`gate.go`) dengan test store-level dan integrasi HTTP (`*_test.go`) yang
menegakkan seluruh keputusan di bawah — termasuk suite cross-tenant-group leak
yang §"Mitigasi" wajibkan.

### 1. Model data (app-level, bukan tamper core)

```
tenant.Descriptor{ID: "tg-acme",  Slug: "acme",      ParentID: "",        Status: Active}  // tenant-group
tenant.Descriptor{ID: "org-1",    Slug: "org-1",     ParentID: "tg-acme", Status: Active}  // organization anak
tenant.Descriptor{ID: "org-2",    Slug: "org-2",     ParentID: "tg-acme", Status: Active}
```

Tabel app sendiri (bukan tamper): `tenant_hierarchy_cache` atau cukup query
`tenant` store dengan index pada `parent_id` — materialized, bukan dihitung
ulang tiap request. Platform admin tidak punya row `Descriptor` sama sekali;
itu konsep murni app-level (role global, lihat §3).

### 2. Resolusi tenant per-request — pin di level tenant-group

`RequireTenant` (espresso) melakukan satu pengecekan: `claims.TenantID ==
resolve(r)`. Karena itu level pin menentukan siapa yang bisa mencapai route
mana. ADR ini memilih **pin di tenant-group yang memiliki org di path**,
bukan di organization:

```go
// resolve = app-level, di atas OrgHierarchy (§4). Membaca org di path,
// mencari parent tenant-group-nya, dan mengembalikan ITU. Org root (tanpa
// parent) pin ke dirinya sendiri; org tak dikenal — yang ParentOf-nya juga
// false — pin ke id-nya sendiri, yang tidak akan cocok dengan token grup
// mana pun.
resolve := tenanthierarchy.TenantGroupResolve(hier, "org_id")

router.Use(
    tamperespresso.RequireAuth(jwtSvc, ...),
    tamperespresso.RequireTenant(resolve), // 1 token = 1 tenant-group
)
```

Alasan (koreksi terhadap draf awal ADR ini): kalau pin tetap di
organization, satu token tenant-group admin hanya bisa cocok dengan SATU org
anak — setiap saudara kandungnya ditolak 401 oleh `RequireTenant` sebelum
authz jalan, dan premis "satu grup, banyak org" mustahil. Dengan pin di grup,
satu token mencapai semua org anak; otorisasi per-org tetap diputuskan
`DecisionGate` seperti §4a. `RequireTenant` sendiri tidak berubah — yang
berubah hanya nilai yang dikembalikan resolver.

Konsekuensi yang harus disadari: `RequireTenant` menyimpan grup sebagai
request tenant, jadi mutasi ber-scope org ter-audit dengan `tenant_id` = grup
dan organisation di `resource_id` (§7). Itu memang batas isolasi yang benar.
Platform admin tidak punya `tid` yang cocok dengan route org mana pun; ia
memakai permukaan **untenanted** `/platform/**` (§5), di mana `RequireTenant`
tidak dipasang.

### 3. Role/subject taxonomy (app-level, 3 scope)

```go
authz.Subject{Type: "user", ID: userID}            // tidak berubah

// resource types baru yang app definisikan, tamper tidak tahu ini:
authz.Resource{Type: "organization", ID: "org-1"}   // sudah ada polanya
authz.Resource{Type: "tenant_group", ID: "tg-acme"}  // BARU
// platform admin = binding GLOBAL, resource_type="system", resource_id=""
// (pola yang authz sketch sudah tunjukkan lewat `ListResources`/unbounded)
```

`BindingStore` (app-implemented, mengikuti kontrak `tamper/authz/store.go`)
menyimpan role binding di 3 scope:

| Scope | `resource_type` | `resource_id` | Contoh |
|---|---|---|---|
| Platform admin | `system` | `""` (global) | superuser, lintas semua tenant-group |
| Tenant-group admin | `tenant_group` | `tg-acme` | reseller, lintas org anak tg-acme |
| Organization admin | `organization` | `org-1` | existing — satu organisasi |

### 4. Expand-before-check: titik paling kritis

Tenant-group admin TIDAK dicek lewat `authz.Check(sub, act, Resource{Type:"organization", ID:"org-1"})`
secara langsung — karena `BindingStore` app itu tidak tahu "tg-acme adalah
parent dari org-1" KECUALI logic expand dijalankan. Dua pola yang disahkan,
pilih salah satu per use-case (TIDAK dicampur dalam satu endpoint):

**4a. Eager expand di `PermissionStore`/`BindingStore` (disarankan default)**

`BindingStore.BindingsForSubject` (app-implemented) melakukan JOIN sendiri
saat resolve binding:

```sql
-- binding tenant_group otomatis "mengembang" jadi binding organization
-- di level STORE, authz.Authorizer tidak pernah tahu ada hierarchy.
-- Role di-TRANSLATE lewat role_translation (fail-closed: role tanpa mapping
-- TIDAK ikut ter-expand), dan hanya org aktif yang ikut.
SELECT 'organization' AS resource_type, o.id AS resource_id, rt.to_role AS role
FROM role_binding rb
JOIN tenant o ON o.parent_id = rb.resource_id AND o.status = 'active'
JOIN role_translation rt
  ON rt.from_resource_type = 'tenant_group'
 AND rt.from_role = rb.role
WHERE rb.subject_id = $1 AND rb.resource_type = 'tenant_group'
UNION
SELECT resource_type, resource_id, role FROM role_binding
WHERE subject_id = $1 AND resource_type = 'organization'
```

`authz.Authorizer.Check(sub, "org:manage", Resource{"organization","org-1"})`
tetap satu call biasa — Authorizer TIDAK tahu hierarchy ada, persis prinsip
"engine stays a dumb, auditable set test" (PHASE5 sketch §3.1). Hierarchy
cost dipindah ke store/SQL, bukan ke call-site atau ke engine.

Dua hal yang draf awal ADR ini lewatkan dan SQL di atas sudah menutup: role
di-TRANSLATE lewat `RoleMap` (fail-closed — role tanpa mapping tidak
mengembang sama sekali, bukan diteruskan mentah), dan org non-aktif
difilter (`o.status = 'active'`). Implementasi referensi
(`examples/tenanthierarchy/bindingstore.go`) memakai `RoleMap` Go, bukan tabel
`role_translation` SQL; keduanya semantik yang sama.

**4b. `ListResources` dengan unbounded flag (dipakai untuk listing/laporan)**

```go
resources, unbounded, err := authorizer.ListResources(ctx, subject, "org:view", "organization")
// HANYA requirement beda-tipe (mis. system/platform_admin) yang dibaca
// authz.RBAC sebagai unbounded=true. Tenant-group admin SELALU enumerable:
// hasilnya daftar org anak konkret, bukan unbounded.
// platform admin (system bypass) → unbounded=true; app skip filtering,
//   persis resi ADR-0020 §3 untuk admin organisasi
// tenant-group admin → resources = daftar org anak konkret; app filter per-org
```

Ini DIPAKAI untuk laporan lintas-organisasi (tenant-group admin lihat
dashboard gabungan N organisasi) — bukan untuk single-resource mutation check.

### 5. Espresso wiring — `DecisionGate` dua-tingkat untuk endpoint org-scoped

Endpoint yang bisa diakses baik org-admin (langsung) MAUPUN tenant-group-admin
(lewat expand) tetap SATU `DecisionGate`, karena expand terjadi di store
(§4a) — call-site espresso tidak berubah SAMA SEKALI:

```go
router.Use(tamperespresso.RequireDecision(tamperespresso.DecisionGate{
    Authorizer:       authorizer,       // authz.Authorizer yang sudah wired expand §4a
    Label:            "organization role",
    SubjectType:       "user",
    ResourceType:      "organization",
    ResourceIDFrom:    "org_id",
    VisibilityAction:  "org:view",       // 404 kalau tidak visible — berlaku jg utk org admin maupun tenant-group admin
    Action:            "org:manage",
    WriteNotVisible:   writeOrgNotFound, // 404, BUKAN 403 — §6 di bawah
    WriteDenied:       writeInsufficientRole,
}))
```

Endpoint KHUSUS tenant-group (mis. `/tenant-groups/{tg_id}/organizations` —
listing org anak, dashboard agregat) pakai `DecisionGate` baru dengan
`ResourceType: "tenant_group"`:

```go
router.Use(tamperespresso.RequireDecision(tamperespresso.DecisionGate{
    Authorizer:    authorizer,
    Label:         "tenant-group role",
    ResourceType:  "tenant_group",
    ResourceIDFrom: "tg_id",
    Action:        "tenant_group:manage",
    WriteDenied:   writeInsufficientRole,
}))
```

Platform-admin endpoint (`/platform/**`) memakai `DecisionGate` dengan
`ResourceIDFrom: ""` (singleton/system-scope, pola yang `DecisionGate` sudah
dukung — lihat komentar "singleton admin gates" di `decision.go`) dan
**tidak memasang `RequireTenant`**: ini permukaan untenanted. Token platform
admin di-mint dengan `tenant.Single` (`tid=""`); memasang `RequireTenant` di
sini akan menolak token itu di route ber-tenant (§2).

### 6. Deny/miss discipline — dua lapis, dan yang byte-identical adalah 401 di gate depan

Disiplin ditegakkan di DUA lapis, bukan satu:

**Lapis tenant gate** (`RequireTenant`). Org milik grup lain, org tak
dikenal, org root yang bukan milik grup subjek, dan token invalid semuanya
menghasilkan `writeUnauthenticated` — 401 yang byte-identical (mekanisme yang
espresso/tenantgate.go sudah pakai). Tidak ada oracle keberadaan org maupun
grup: `TenantGroupResolve` tidak pernah mengembalikan sinyal "ada/tidak ada",
hanya sebuah id yang cocok atau tidak.

**Lapis authz** (`DecisionGate`, hanya untuk request yang sudah ter-pin ke
grup subjek). `VisibilityAction` + `WriteNotVisible` (404) untuk org yang
tidak visible, `WriteDenied` (403) untuk role yang terlihat tapi kurang
rank-nya.

Jadi klaim draf awal ADR ini ("tenant-group admin di luar hierarki dapat 404
byte-identical dengan org tidak ada") dikoreksi: yang byte-identical adalah
**401 di gate depan**. 404 hanya muncul untuk org yang sudah ter-pin ke grup
subjek tapi tidak visible. Ini tidak membocorkan keberadaan org — subjek
sudah tahu keanggotaan grupnya sendiri; yang tetap tak terbedakan adalah
"org ini ada di grup lain / tidak eksis sama sekali".

### 7. Audit — satu chain, tidak ada chain per tenant-group

`Auditor.For(MutationContext{...})` tetap dipakai apa adanya di semua level.
Platform-admin dan tenant-group-admin mutation tetap masuk SATU audit chain
(keputusan M5 tamper yang sudah settled).

Level admin TIDAK dibedakan lewat `actor.subject_type`: `Subject.Type` adalah
`"user"` untuk ketiga level, dan `audit.ActorType` hanya punya
`user`/`service_account`/`system` — tidak ada `platform_admin` maupun
`tenant_group_admin` di sana. Level adalah ROLE, bukan tipe subjek. Kalau perlu
dibedakan saat query, simpan role/scope-nya di field lain (mis. `resource`
yang memuat tipe `system`/`tenant_group`/`organization`, atau kolom metadata
app) — bukan dengan mengarang nilai `subject_type`, dan bukan chain baru.

Dengan pin di tenant-group (§2), `tenant_id` di baris audit ber-scope org
adalah grup pemiliknya; organisation ada di `resource_id`.

### 8. Entitlement tidak mewarisi otomatis

`tenant.EntitlementStore.ForTenant(orgID)` tetap per-organization. Kalau
tenant-group punya plan yang "diturunkan" ke org anak, itu LOGIC APP
tersendiri (mis. saat provisioning org baru di bawah tenant-group, COPY
entitlement values) — bukan inheritance runtime. tamper tidak dan tidak akan
punya konsep ini.

## Knowledge Flow (Visual)

Lima diagram — struktur data, request masuk, expand-before-check (jantung
keputusan ini), dua pola authz call, dan deny/audit discipline. Baca
urut; tiap diagram membangun di atas yang sebelumnya.

### 1. Struktur hierarki — siapa punya row apa

```
┌─────────────────────────────────────────────────────────────────┐
│ PLATFORM                                                         │
│   bukan tenant.Descriptor — konsep app-level murni.              │
│   authz binding: Resource{Type:"system", ID:""}  (global)        │
└───────────────────────────┬───────────────────────────────────────┘
                            │ app-level "owns many"
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ TENANT-GROUP  (reseller / distributor)                           │
│   tenant.Descriptor{ID:"tg-acme", ParentID:""}                   │
│   authz binding: Resource{Type:"tenant_group", ID:"tg-acme"}     │
└───────────────────────────┬───────────────────────────────────────┘
                            │ tenant.Descriptor.ParentID
                            │ (RESERVED di tamper — dibaca app sendiri
                            │  lewat OrgHierarchy.ChildrenOf, TIDAK
                            │  pernah oleh tamper.tenant.Store)
                ┌───────────┼───────────┐
                ▼           ▼           ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  org-1   │ │  org-2   │ │  org-3   │   tenant.Descriptor{
        │ ParentID:│ │ ParentID:│ │ ParentID:│     ID, ParentID:"tg-acme"
        │ "tg-acme"│ │ "tg-acme"│ │ "tg-acme"│   }
        └──────────┘ └──────────┘ └──────────┘
          authz binding: Resource{Type:"organization", ID:"org-N"}
```

### 2. Request masuk — pin di tenant-group (bukan organization)

```
HTTP request  (subdomain / path / header org_id)
        │
        ▼
tamperespresso.RequireAuth(jwtSvc)       ← verifikasi JWT, claims ke context
        │
        ▼
tamperespresso.RequireTenant(resolve)    ← PIN 1 tenant-group, cross-check
        │                                   claims.TenantID == tenant-group
        │                                   pemilik org di path (resolve =
        │                                   TenantGroupResolve, §2)
        ▼
ctx sekarang bawa: tenant GROUP yang di-pin (bukan org)
        │
        ▼
tamperespresso.RequireDecision(DecisionGate{...})   ← lanjut ke diagram 3
```
Tenant-group-lah yang di-pin `RequireTenant`; org adalah RESOURCE di dalamnya
yang diperiksa authz. Itulah sebab §4 (expand) jadi titik krusial, dan
sekaligus sebab satu token tenant-group admin bisa mencapai banyak org anak.

### 3. Expand-before-check — jantung keputusan ini (§4a)

```
authz.Authorizer.Check(sub, "org:manage", Resource{"organization","org-1"})
        │
        ▼
   RBAC.effective(ctx, sub, Resource{"organization","org-1"})
        │
        ▼
   store.BindingsFor(ctx, sub, res)     ← store = tenanthierarchy.Store
        │                                  (WRAPPER di atas authz.BindingStore,
        │                                   authz.RBAC TIDAK TAHU ini terjadi)
        ▼
   ┌─────────────────────────────────────────────────────────┐
   │ 1. base.BindingsFor(sub, {"organization","org-1"})       │
   │    → binding LANGSUNG di org-1, kalau ada                │
   │                                                            │
   │ 2. hier.ParentOf(ctx, "org-1") → "tg-acme"               │
   │    (query app sendiri — BUKAN tamper.tenant.Store)        │
   │                                                            │
   │ 3. base.BindingsFor(sub, {"tenant_group","tg-acme"})     │
   │    → binding tenant-group-admin, kalau subject punya      │
   │                                                            │
   │ 4. roles.translate(role)  → role organization yang sepadan│
   │    (fail-closed kalau role tidak ada di RoleMap)          │
   │                                                            │
   │ 5. RE-STAMP: Binding{sub, {"organization","org-1"}, role} │
   │    ← resource di-GANTI jadi org-1, BUKAN tenant_group lagi│
   └─────────────────────────────────────────────────────────┘
        │
        ▼
   union(1) + (5)  →  dikembalikan ke RBAC.effective SEBAGAI
                       binding org-1 BIASA — engine evaluasi rank
                       seolah ini binding langsung, tanpa tahu
                       asalnya dari tenant-group mana pun.
        │
        ▼
   Decision{Allowed: true/false}   ← satu jawaban, satu call-site,
                                      TIDAK ADA perubahan di espresso
                                      DecisionGate atau RBAC engine.
```
Ini sebabnya ADR menolak Alternatif A (resolve `ParentID` di tamper core) —
expand terjadi SELURUHNYA di `Store` wrapper milik app, satu langkah sebelum
jawaban sampai ke engine yang "dumb".

### 4. Dua pola pemakaian — jangan dicampur (§4a vs §4b)

```
             ┌───────────────────────────────────────────┐
             │   Apa yang mau dijawab?                    │
             └──────────────┬──────────────┬───────────────┘
                             │              │
          "boleh MUTASI 1 org  "LIST semua org yang boleh
           ini?" (mutation/     dilihat subject ini?"
           single-resource)     (listing/dashboard/laporan)
                             │              │
                             ▼              ▼
                     §4a eager expand   §4b ListResources
                   (BindingsFor via     (authz.Authorizer.
                    tenanthierarchy.     ListResources, baca
                    Store, re-stamp      unbounded flag —
                    1 resource)          app skip filter kalau
                             │           unbounded=true)
                             ▼              ▼
                   DecisionGate single   dashboard/report
                   endpoint (org_id      tenant-group admin:
                   dari path param)      N organisasi sekaligus,
                                         tanpa N kali Check()
```

### 5. Deny & audit — dua lapis deny, satu chain audit

```
                 org TIDAK ADA           org ADA, tapi di GRUP LAIN
                 (org_id salah)          atau org root bukan milik subjek
                        │                        │
                        └──────────┬─────────────┘
                                   ▼
                        401  (BYTE-IDENTICAL)
                        — di TENANT GATE, sebelum authz jalan. Tidak bisa
                          dibedakan dari token invalid. Tidak ada sinyal
                          "org ini ada" maupun "grup ini ada".

                 org ADA di grup subjek, tapi TIDAK VISIBLE
                                   │
                                   ▼
                        404  (DecisionGate WriteNotVisible)

                 org ADA & visible, role KURANG rank
                                   │
                                   ▼
                        403  (DecisionGate WriteDenied)

                        mutation BERHASIL (level apa pun)
                                   │
                                   ▼
                  espresso.Auditor.For(MutationContext{...})
                                   │
                                   ▼
                  audit.Event{ actor, resource_id, tenant_id }
                                   │
                                   ▼
                  SATU chain hash (M5 tamper, tidak ada chain
                  baru per tenant-group) — level admin dibedakan
                  lewat role/resource di baris audit, BUKAN lewat
                  actor.subject_type (yang selalu "user")
```

## Alternatif yang dipertimbangkan

### A. Resolve `ParentID` di dalam tamper core (ubah `tenant` package)
Tambah method `Store.Children(ctx, parentID)` atau auto-walk `ParentID` di
`RequireTenant`. **Ditolak** — melanggar langsung invariant Phase 7 yang
sudah tertulis eksplisit ("Nothing in tamper resolves it, inherits through
it, or branches on it") dan test yang sudah ada
(`TestMemStore_ParentIDCarriedNotResolved`). Mengubah ini butuh amend sketch
Phase 7 dulu, bukan keputusan yang bisa diambil sepihak di consumer app, dan
tamper's "names no table" principle berarti hierarchy logic MEMANG bukan
tempatnya di core.

### B. `RequireTenant` menerima banyak tenant ID sekaligus (multi-tenant pin)
Supaya tenant-group admin bisa langsung "pin" ke N organisasi dalam satu
request context. **Ditolak** — `RequireTenant` sengaja didesain single-tenant
pin per request (cross-check 1-ke-1 dengan token `tid`); multi-pin
menghilangkan properti itu dan bikin setiap handler harus tahu cara iterate
tenant list, padahal `ListResources` (§4b) sudah menjawab kebutuhan yang sama
tanpa mengubah kontrak `RequireTenant`.

### C. Platform admin sebagai row `tenant.Descriptor` tersendiri (ID khusus "PLATFORM")
Supaya platform admin "punya" tenant row juga, konsisten dengan dua level
lain. **Ditolak** — platform admin BUKAN tenant, dan memaksanya jadi row
tenant berarti `RequireTenant` harus punya case khusus untuk ID itu, membuka
lubang baru (apa yang terjadi kalau row itu ke-suspend?). Lebih aman platform
admin murni binding `resource_type="system"` tanpa Descriptor sama sekali —
sejalan dengan prinsip "tamper does not know platform exists" kita.

## Konsekuensi

**Positif**
- tamper core (0 baris diubah) — upgrade tamper tetap aman, hierarchy logic
  sepenuhnya milik app dan bisa di-iterate tanpa fork tamper.
- `espresso` call-site TIDAK berubah untuk endpoint organization-scoped yang
  sudah ada — `DecisionGate` existing otomatis "mengerti" tenant-group admin
  begitu `BindingStore` diupdate (§4a), karena expand terjadi di store bukan
  di middleware.
- Non-enumerability + audit single-chain tetap berlaku utuh: cross-group /
  unknown / root → 401 byte-identical di tenant gate (§6), in-group invisible
  → 404, under-ranked → 403. Tidak ada permukaan baru untuk cross-tenant-group
  enumeration.

**Negatif / biaya yang diterima**
- Expand JOIN (§4a) jadi query tambahan di hot path SETIAP check ber-scope
  organization, bukan hanya request tenant-group-admin: store harus membaca
  parent sebelum tahu subject-nya admin grup atau bukan, jadi `ParentOf` +
  `BindingsFor(tenant_group)` jalan untuk org-admin biasa juga. Perlu index
  pada `tenant.parent_id` dan kemungkinan caching (binding jarang berubah, TTL
  cache aman).
- Dua pola expand (§4a eager-join vs §4b ListResources-unbounded) harus
  dipakai KONSISTEN per use-case; developer baru bisa salah pilih (mutation
  pakai §4b yang tidak cocok untuk single-resource check, atau §4a dipakai
  untuk listing besar yang lebih mahal dari unbounded flag).
- Platform-admin HTTP surface adalah permukaan risiko baru yang resi
  (consumer house lain) sengaja TIDAK punya (ADR resi: cross-tenant ops
  CLI-only). Keputusan ini TIDAK otomatis berarti resi harus ikut — ini
  keputusan untuk app yang memang butuh platform-admin lewat HTTP.
- Mutasi ber-scope organization ter-audit dengan `tenant_id` = tenant-group
  pemiliknya dan organisation di `resource_id` (§2), bukan `tenant_id` = org.
  Itu konsekuensi dari pin di grup; app yang butuh tenant_id per-org di audit
  harus menyimpannya di field lain.
- Tidak ada test harness tamper sendiri yang memverifikasi pola ini (beda
  dengan `identity.TenantScopedStore` conformance harness yang tamper
  sediakan) — app yang implement WAJIB menulis sendiri cross-tenant-group
  leak suite-nya, mengikuti pola sketch §3.3 secara manual.

**Mitigasi**
- Cross-tenant-group leak test WAJIB ada sebelum merge: tenant-group-admin A
  mencoba akses org milik tenant-group B ditolak, dibuktikan test eksplisit di
  layer authz app DAN di wire (401 dari tenant gate) — lihat
  `examples/tenanthierarchy/`.
- Dedup binding di store HARUS per `(resource, role)` / `(subject, role)`,
  bukan per resource/subject saja: subjek bisa punya role direct ber-rank
  rendah plus role warisan ber-rank tinggi di resource yang sama, dan dedup
  yang salah membuat `ListResources`/`ListSubjects` under-report.
- `BindingsForSubject`/expand query di-cache dengan TTL pendek (binding
  hierarchy berubah jarang — provisioning event, bukan tiap request).
- Dokumentasikan sekali di app-level README: §4a dipakai untuk SETIAP
  single-resource `Check`, §4b HANYA untuk listing/dashboard — supaya
  developer baru tidak menebak.

## Kapan keputusan ini perlu ditinjau ulang

Kalau (a) jumlah level hierarchy tumbuh jadi >3 (mis. reseller-of-reseller) —
expand JOIN §4a jadi rekursif dan butuh CTE/materialized closure table,
pertimbangkan ulang apakah tamper core perlu amend sketch Phase 7 §8 item 3
untuk native nested-tenant support; atau (b) volume tenant-group tumbuh besar
sampai eager-expand jadi bottleneck authz hot path — saat itu pertimbangkan
precompute binding efektif ke tabel denormalisasi saat provisioning, bukan
join on-the-fly.
