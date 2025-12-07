#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>

#define MAX_WORDS 16
#define TEA_DELTA 0x9E3779B9u
#define XTEA_ROUNDS 32

static inline uint8_t rotl8(uint8_t value, uint8_t count) {
    count &= 7u;
    if (count == 0u) {
        return value;
    }
    return (uint8_t)((uint32_t)(value << count) | (value >> (8u - count)));
}

static inline uint8_t rotr8(uint8_t value, uint8_t count) {
    count &= 7u;
    if (count == 0u) {
        return value;
    }
    return (uint8_t)((uint32_t)(value >> count) | (value << (8u - count)));
}

static inline uint32_t mx(uint32_t y, uint32_t z, uint32_t sum, uint32_t key_val) {
    uint32_t term1 = ((z >> 5) ^ (y << 2));
    uint32_t term2 = ((y >> 3) ^ (z << 4));
    uint32_t term3 = (sum ^ y);
    uint32_t term4 = (key_val ^ z);
    return (term1 + term2) ^ (term3 + term4);
}

static void xtea_encrypt_word_impl(uint32_t *v0, uint32_t *v1, const uint32_t *key) {
    uint32_t sum = 0u;
    uint32_t val0 = *v0;
    uint32_t val1 = *v1;

    for (int i = 0; i < XTEA_ROUNDS; ++i) {
        uint32_t temp = ((val1 << 4) ^ (val1 >> 5)) + val1;
        temp ^= sum + key[sum & 3u];
        val0 = (val0 + temp) & 0xFFFFFFFFu;

        sum = (sum + TEA_DELTA) & 0xFFFFFFFFu;

        temp = ((val0 << 4) ^ (val0 >> 5)) + val0;
        temp ^= sum + key[(sum >> 11) & 3u];
        val1 = (val1 + temp) & 0xFFFFFFFFu;
    }

    *v0 = val0;
    *v1 = val1;
}

static void xtea_decrypt_word_impl(uint32_t *v0, uint32_t *v1, const uint32_t *key) {
    uint32_t sum = 0u;
    uint32_t val0 = *v0;
    uint32_t val1 = *v1;

    // Calculate initial sum
    for (int i = 0; i < XTEA_ROUNDS; ++i) {
        sum = (sum + TEA_DELTA) & 0xFFFFFFFFu;
    }

    for (int i = 0; i < XTEA_ROUNDS; ++i) {
        uint32_t temp = ((val0 << 4) ^ (val0 >> 5)) + val0;
        temp ^= sum + key[(sum >> 11) & 3u];
        val1 = (val1 - temp) & 0xFFFFFFFFu;

        sum = (sum - TEA_DELTA) & 0xFFFFFFFFu;

        temp = ((val1 << 4) ^ (val1 >> 5)) + val1;
        temp ^= sum + key[sum & 3u];
        val0 = (val0 - temp) & 0xFFFFFFFFu;
    }

    *v0 = val0;
    *v1 = val1;
}

static int ensure_uint8_buffer(Py_buffer *view, const char *name) {
    if (view->itemsize != 1) {
        PyErr_Format(PyExc_TypeError, "Buffer for %s must have itemsize 1", name);
        return 0;
    }
    if (!PyBuffer_IsContiguous(view, 'C')) {
        PyErr_Format(PyExc_ValueError, "%s buffer must be C-contiguous", name);
        return 0;
    }
    if (view->len < 0) {
        PyErr_Format(PyExc_ValueError, "%s buffer length is invalid", name);
        return 0;
    }
    return 1;
}

static int ensure_uint32_buffer(Py_buffer *view, Py_ssize_t min_items, const char *name) {
    if (view->itemsize != (Py_ssize_t)sizeof(uint32_t)) {
        PyErr_Format(PyExc_TypeError, "Buffer for %s must have itemsize %zu", name, sizeof(uint32_t));
        return 0;
    }
    if (!PyBuffer_IsContiguous(view, 'C')) {
        PyErr_Format(PyExc_ValueError, "%s buffer must be C-contiguous", name);
        return 0;
    }
    if ((Py_ssize_t)view->len < min_items * (Py_ssize_t)sizeof(uint32_t)) {
        PyErr_Format(PyExc_ValueError, "%s buffer is too small", name);
        return 0;
    }
    return 1;
}

static void encrypt_block_impl(uint32_t *v, const uint32_t *key, int n) {
    uint32_t rounds = 6u + (uint32_t)(52 / n);
    uint32_t sum = 0u;
    uint32_t z = v[n - 1];

    for (uint32_t i = 0u; i < rounds; ++i) {
        sum = (sum + TEA_DELTA) & 0xFFFFFFFFu;
        uint32_t e = (sum >> 2) & 3u;

        for (int p = 0; p < n - 1; ++p) {
            uint32_t y = v[p + 1];
            uint32_t mx_val = mx(y, z, sum, key[(p & 3) ^ e]);
            v[p] = (v[p] + mx_val) & 0xFFFFFFFFu;
            z = v[p];
        }

        uint32_t y = v[0];
        uint32_t mx_val = mx(y, z, sum, key[((n - 1) & 3) ^ e]);
        v[n - 1] = (v[n - 1] + mx_val) & 0xFFFFFFFFu;
        z = v[n - 1];
    }
}

static void decrypt_block_impl(uint32_t *v, const uint32_t *key, int n) {
    uint32_t rounds = 6u + (uint32_t)(52 / n);
    uint32_t sum = (rounds * TEA_DELTA) & 0xFFFFFFFFu;
    uint32_t y = v[0];

    while (sum != 0u) {
        uint32_t e = (sum >> 2) & 3u;

        for (int p = n - 1; p > 0; --p) {
            uint32_t z = v[p - 1];
            uint32_t mx_val = mx(y, z, sum, key[(p & 3) ^ e]);
            v[p] = (v[p] - mx_val) & 0xFFFFFFFFu;
            y = v[p];
        }

        uint32_t z = v[n - 1];
        uint32_t mx_val = mx(y, z, sum, key[0 ^ e]);
        v[0] = (v[0] - mx_val) & 0xFFFFFFFFu;
        y = v[0];

        sum = (sum - TEA_DELTA) & 0xFFFFFFFFu;
    }
}

static PyObject *crypto_simple_cryptor_encrypt_bytes(PyObject *self, PyObject *args) {
    Py_buffer buf_view;
    Py_buffer key_view;

    if (!PyArg_ParseTuple(args, "w*y*", &buf_view, &key_view)) {
        return NULL;
    }

    if (!ensure_uint8_buffer(&buf_view, "buf")) {
        PyBuffer_Release(&buf_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (!ensure_uint8_buffer(&key_view, "key")) {
        PyBuffer_Release(&buf_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (key_view.len < 16) {
        PyBuffer_Release(&buf_view);
        PyBuffer_Release(&key_view);
        PyErr_SetString(PyExc_ValueError, "Key buffer must contain at least 16 bytes");
        return NULL;
    }

    uint8_t *buf = (uint8_t *)buf_view.buf;
    const uint8_t *key = (const uint8_t *)key_view.buf;
    Py_ssize_t buf_len = buf_view.len;
    uint8_t prev_encrypted = 0u;

    for (Py_ssize_t i = 0; i < buf_len; ++i) {
        uint8_t key_byte = key[i & 15];
        uint32_t sum_val = (uint32_t)buf[i] + (uint32_t)(key_byte >> 2);
        uint8_t value = (uint8_t)(sum_val & 0xFFu);

        Py_ssize_t remaining = buf_len - i;
        uint8_t rot_mod = (uint8_t)(((uint32_t)prev_encrypted + (uint32_t)(remaining % 7)) % 7u);
        uint8_t key_rot = rotl8(key[15 - (i & 15)], rot_mod);
        value ^= key_rot;

        uint32_t inv = (~(uint32_t)prev_encrypted) & 0xFFFFFFFFu;
        uint8_t final_shift = (uint8_t)(inv % 7u);
        value = rotr8(value, final_shift);

        prev_encrypted = value;
        buf[i] = value;
    }

    PyBuffer_Release(&buf_view);
    PyBuffer_Release(&key_view);
    Py_RETURN_NONE;
}

static PyObject *crypto_simple_cryptor_decrypt_bytes(PyObject *self, PyObject *args) {
    Py_buffer buf_view;
    Py_buffer key_view;

    if (!PyArg_ParseTuple(args, "w*y*", &buf_view, &key_view)) {
        return NULL;
    }

    if (!ensure_uint8_buffer(&buf_view, "buf")) {
        PyBuffer_Release(&buf_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (!ensure_uint8_buffer(&key_view, "key")) {
        PyBuffer_Release(&buf_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (key_view.len < 16) {
        PyBuffer_Release(&buf_view);
        PyBuffer_Release(&key_view);
        PyErr_SetString(PyExc_ValueError, "Key buffer must contain at least 16 bytes");
        return NULL;
    }

    uint8_t *buf = (uint8_t *)buf_view.buf;
    const uint8_t *key = (const uint8_t *)key_view.buf;
    Py_ssize_t buf_len = buf_view.len;
    uint8_t prev_encrypted = 0u;

    for (Py_ssize_t i = 0; i < buf_len; ++i) {
        uint8_t tmp_e = buf[i];
        uint32_t inv = (~(uint32_t)prev_encrypted) & 0xFFFFFFFFu;
        uint8_t shift = (uint8_t)(inv % 7u);
        uint8_t value = rotl8(buf[i], shift);

        Py_ssize_t remaining = buf_len - i;
        uint8_t rot_mod = (uint8_t)(((uint32_t)prev_encrypted + (uint32_t)(remaining % 7)) % 7u);
        uint8_t key_rot = rotl8(key[15 - (i & 15)], rot_mod);
        value ^= key_rot;

        uint8_t key_byte = key[i & 15];
        int32_t diff = (int32_t)value - (int32_t)(key_byte >> 2);
        value = (uint8_t)((uint32_t)diff & 0xFFu);

        buf[i] = value;
        prev_encrypted = tmp_e;
    }

    PyBuffer_Release(&buf_view);
    PyBuffer_Release(&key_view);
    Py_RETURN_NONE;
}

static PyObject *crypto_xxtea_encrypt_block(PyObject *self, PyObject *args) {
    Py_buffer v_view;
    Py_buffer key_view;
    Py_ssize_t n;

    if (!PyArg_ParseTuple(args, "w*y*n", &v_view, &key_view, &n)) {
        return NULL;
    }

    if (n <= 1 || n > MAX_WORDS) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        PyErr_SetString(PyExc_ValueError, "n must be between 2 and 16");
        return NULL;
    }

    if (!ensure_uint32_buffer(&v_view, n, "v")) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (!ensure_uint32_buffer(&key_view, 4, "key")) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    encrypt_block_impl((uint32_t *)v_view.buf, (const uint32_t *)key_view.buf, (int)n);

    PyBuffer_Release(&v_view);
    PyBuffer_Release(&key_view);
    Py_RETURN_NONE;
}

static PyObject *crypto_xxtea_decrypt_block(PyObject *self, PyObject *args) {
    Py_buffer v_view;
    Py_buffer key_view;
    Py_ssize_t n;

    if (!PyArg_ParseTuple(args, "w*y*n", &v_view, &key_view, &n)) {
        return NULL;
    }

    if (n <= 1 || n > MAX_WORDS) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        PyErr_SetString(PyExc_ValueError, "n must be between 2 and 16");
        return NULL;
    }

    if (!ensure_uint32_buffer(&v_view, n, "v")) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (!ensure_uint32_buffer(&key_view, 4, "key")) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    decrypt_block_impl((uint32_t *)v_view.buf, (const uint32_t *)key_view.buf, (int)n);

    PyBuffer_Release(&v_view);
    PyBuffer_Release(&key_view);
    Py_RETURN_NONE;
}

static PyObject *crypto_xxtea_encrypt_block_fixed(PyObject *self, PyObject *args) {
    Py_buffer v_view;
    Py_buffer key_view;

    if (!PyArg_ParseTuple(args, "w*y*", &v_view, &key_view)) {
        return NULL;
    }

    if (!ensure_uint32_buffer(&v_view, MAX_WORDS, "v")) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (!ensure_uint32_buffer(&key_view, 4, "key")) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    encrypt_block_impl((uint32_t *)v_view.buf, (const uint32_t *)key_view.buf, MAX_WORDS);

    PyBuffer_Release(&v_view);
    PyBuffer_Release(&key_view);
    Py_RETURN_NONE;
}

static PyObject *crypto_xxtea_decrypt_block_fixed(PyObject *self, PyObject *args) {
    Py_buffer v_view;
    Py_buffer key_view;

    if (!PyArg_ParseTuple(args, "w*y*", &v_view, &key_view)) {
        return NULL;
    }

    if (!ensure_uint32_buffer(&v_view, MAX_WORDS, "v")) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (!ensure_uint32_buffer(&key_view, 4, "key")) {
        PyBuffer_Release(&v_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    decrypt_block_impl((uint32_t *)v_view.buf, (const uint32_t *)key_view.buf, MAX_WORDS);

    PyBuffer_Release(&v_view);
    PyBuffer_Release(&key_view);
    Py_RETURN_NONE;
}

static PyObject *crypto_xxtea_encrypt_blocks(PyObject *self, PyObject *args) {
    Py_buffer data_view;
    Py_buffer key_view;
    Py_ssize_t block_count;

    if (!PyArg_ParseTuple(args, "w*y*n", &data_view, &key_view, &block_count)) {
        return NULL;
    }

    if (block_count < 0) {
        PyBuffer_Release(&data_view);
        PyBuffer_Release(&key_view);
        PyErr_SetString(PyExc_ValueError, "block_count must be non-negative");
        return NULL;
    }

    if (!ensure_uint32_buffer(&data_view, block_count * MAX_WORDS, "data")) {
        PyBuffer_Release(&data_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (!ensure_uint32_buffer(&key_view, 4, "key")) {
        PyBuffer_Release(&data_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    uint32_t *data = (uint32_t *)data_view.buf;
    const uint32_t *key = (const uint32_t *)key_view.buf;

    for (Py_ssize_t i = 0; i < block_count; ++i) {
        encrypt_block_impl(data + (i * MAX_WORDS), key, MAX_WORDS);
    }

    PyBuffer_Release(&data_view);
    PyBuffer_Release(&key_view);
    Py_RETURN_NONE;
}

static PyObject *crypto_xxtea_decrypt_blocks(PyObject *self, PyObject *args) {
    Py_buffer data_view;
    Py_buffer key_view;
    Py_ssize_t block_count;

    if (!PyArg_ParseTuple(args, "w*y*n", &data_view, &key_view, &block_count)) {
        return NULL;
    }

    if (block_count < 0) {
        PyBuffer_Release(&data_view);
        PyBuffer_Release(&key_view);
        PyErr_SetString(PyExc_ValueError, "block_count must be non-negative");
        return NULL;
    }

    if (!ensure_uint32_buffer(&data_view, block_count * MAX_WORDS, "data")) {
        PyBuffer_Release(&data_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    if (!ensure_uint32_buffer(&key_view, 4, "key")) {
        PyBuffer_Release(&data_view);
        PyBuffer_Release(&key_view);
        return NULL;
    }

    uint32_t *data = (uint32_t *)data_view.buf;
    const uint32_t *key = (const uint32_t *)key_view.buf;

    for (Py_ssize_t i = 0; i < block_count; ++i) {
        decrypt_block_impl(data + (i * MAX_WORDS), key, MAX_WORDS);
    }

    PyBuffer_Release(&data_view);
    PyBuffer_Release(&key_view);
    Py_RETURN_NONE;
}

static PyObject *crypto_xtea_encrypt_word(PyObject *self, PyObject *args) {
    unsigned long v0, v1;
    Py_buffer key_view;

    if (!PyArg_ParseTuple(args, "kky*", &v0, &v1, &key_view)) {
        return NULL;
    }

    if (!ensure_uint32_buffer(&key_view, 4, "key")) {
        PyBuffer_Release(&key_view);
        return NULL;
    }

    uint32_t val0 = (uint32_t)v0;
    uint32_t val1 = (uint32_t)v1;
    xtea_encrypt_word_impl(&val0, &val1, (const uint32_t *)key_view.buf);

    PyBuffer_Release(&key_view);
    return Py_BuildValue("(kk)", (unsigned long)val0, (unsigned long)val1);
}

static PyObject *crypto_xtea_decrypt_word(PyObject *self, PyObject *args) {
    unsigned long v0, v1;
    Py_buffer key_view;

    if (!PyArg_ParseTuple(args, "kky*", &v0, &v1, &key_view)) {
        return NULL;
    }

    if (!ensure_uint32_buffer(&key_view, 4, "key")) {
        PyBuffer_Release(&key_view);
        return NULL;
    }

    uint32_t val0 = (uint32_t)v0;
    uint32_t val1 = (uint32_t)v1;
    xtea_decrypt_word_impl(&val0, &val1, (const uint32_t *)key_view.buf);

    PyBuffer_Release(&key_view);
    return Py_BuildValue("(kk)", (unsigned long)val0, (unsigned long)val1);
}

static PyMethodDef cryptoMethods[] = {
    {"simple_cryptor_encrypt_bytes", crypto_simple_cryptor_encrypt_bytes, METH_VARARGS, "Encrypt bytes in-place using the simple cryptor"},
    {"simple_cryptor_decrypt_bytes", crypto_simple_cryptor_decrypt_bytes, METH_VARARGS, "Decrypt bytes in-place using the simple cryptor"},
    {"xxtea_encrypt_block", crypto_xxtea_encrypt_block, METH_VARARGS, "Encrypt an XXTEA block"},
    {"xxtea_decrypt_block", crypto_xxtea_decrypt_block, METH_VARARGS, "Decrypt an XXTEA block"},
    {"xxtea_encrypt_block_fixed", crypto_xxtea_encrypt_block_fixed, METH_VARARGS, "Encrypt a fixed-size XXTEA block"},
    {"xxtea_decrypt_block_fixed", crypto_xxtea_decrypt_block_fixed, METH_VARARGS, "Decrypt a fixed-size XXTEA block"},
    {"xxtea_encrypt_blocks", crypto_xxtea_encrypt_blocks, METH_VARARGS, "Encrypt multiple XXTEA blocks"},
    {"xxtea_decrypt_blocks", crypto_xxtea_decrypt_blocks, METH_VARARGS, "Decrypt multiple XXTEA blocks"},
    {"xtea_encrypt_word", crypto_xtea_encrypt_word, METH_VARARGS, "Encrypt an XTEA word pair"},
    {"xtea_decrypt_word", crypto_xtea_decrypt_word, METH_VARARGS, "Decrypt an XTEA word pair"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef cryptomodule = {
    PyModuleDef_HEAD_INIT,
    "crypto",
    "C implementations for osz2 crypto primitives",
    -1,
    cryptoMethods
};

PyMODINIT_FUNC PyInit_crypto(void) {
    return PyModule_Create(&cryptomodule);
}
