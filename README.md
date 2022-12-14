<div align="center">

  <h1><code>decrypt-pdf-stream</code></h1>

</div>

## Example

<pre>
    <code>
  import * as wasm from "decrypt-pdf-stream";

  // function get_key(o: string, p: number, id: string, rev: number): Uint8Array;
  get_key(o: string, p: number, id: string): Uint8Array
  var key = wasm.get_key("347a1c17c0286dc0bdad432e7246432b67404a5a19737b19ea10ea0b6b39f89e", -1044, "a07832b34bb0befc21122fcc7cf669f9");

  // In the encrypt and decrypt functions, cfm is only used when rev >= 4.
  // Possible CFM values:
  //   - V2     -> use RC4 algorithm
  //   - AESV2  -> use AES algorithm
  //   - None   -> don't encrypt/decrypt

  // function encrypt(obj_num: number, gen_num: number, key: Uint8Array, stream: Uint8Array, rev: number, cfm: string): Uint8Array;
  var ciphertext = wasm.encrypt(5, 0, key, [0x01, 0x02, 0x03, 0xF0], 3, "");
  console.log(ciphertext)

  // function decrypt(obj_num: number, gen_num: number, key: Uint8Array, stream: Uint8Array, rev: number, cfm: string): Uint8Array;
  var plaintext = wasm.decrypt(5, 0, key, ciphertext, 3, "");
  console.log(plaintext);
    </code>
</pre>

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.