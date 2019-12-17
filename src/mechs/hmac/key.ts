import { JsonProp, JsonPropTypes } from "@peculiar/json-schema";
import * as core from "webcrypto-core";
import { JsonBase64UrlArrayBufferConverter } from "../../converters";
import { CryptoKey } from "../../key";

export class HmacCryptoKey extends CryptoKey {

  @JsonProp({ name: "ext", type: JsonPropTypes.Boolean, optional: true })
  public extractable: boolean;

  public readonly type: KeyType;

  @JsonProp({ name: "key_ops", type: JsonPropTypes.String, repeated: true, optional: true })
  public usages: KeyUsage[];

  @JsonProp({ name: "k", converter: JsonBase64UrlArrayBufferConverter })
  public data: Uint8Array;

  public algorithm: HmacKeyAlgorithm;

  @JsonProp({ type: JsonPropTypes.String })
  protected readonly kty: string = "oct";

  @JsonProp({ type: JsonPropTypes.String })
  protected get alg() {
    const hash = this.algorithm.hash.name.toUpperCase();
    return `HS${hash.replace("SHA-", "")}`;
  }

  protected set alg(value: string) {
    // nothing, cause set is needed for json-schema, but is not used by module
  }

  constructor()
  constructor(
    algorithm: KeyAlgorithm,
    extractable: boolean,
    usages: KeyUsage[],
    data: Uint8Array,
  )
  constructor(
    algorithm = { name: "HMAC" },
    extractable = false,
    usages: KeyUsage[] = [],
    data = new Uint8Array(0),
  ) {
    super(algorithm, extractable, "secret", usages);
    this.data = data;
  }

}
