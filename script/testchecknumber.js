import { checkNumberInfo } from '../src/Utils/number-info.js'

const nomor = (process.argv.slice(2).find(a => !a.startsWith('--')) || process.env.CHECK_NUMBER || '')

if (!nomor) {
    console.error('Pakai: node script/testchecknumber.js <nomor>')
    console.error('Contoh: node script/testchecknumber.js 6281234567890')
    console.error('Nomor juga bisa lewat env CHECK_NUMBER.')
    console.error('')
    console.error('Nomor harus format internasional tanpa 0 di depan. Permintaan tidak butuh')
    console.error('koneksi socket dan tidak pernah meminta kode; hanya membaca /v2/exist.')
    process.exit(2)
}

try {
    const result = await checkNumberInfo(nomor)
    console.log(JSON.stringify(result, null, 2))
}
catch (error) {
    console.error('GAGAL :', error.message)
    console.error('kode  :', error.output?.statusCode ?? '-')
    process.exit(1)
}
