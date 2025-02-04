const { Buffer } = require("buffer");
const secp256k1 = require("secp256k1");
const { keccak256 } = require("js-sha3");

function verifyECDSASignature(
  taskId,
  schema,
  uHash,
  publicFieldsHash,
  signature,
  originAddress,
  recipient
) {
  const types = ["bytes32", "bytes32", "bytes32", "bytes32"];
  const values = [
    stringToHex(taskId),
    stringToHex(schema),
    uHash,
    publicFieldsHash,
  ];

  if (recipient) {
    types.push("address");
    values.push(recipient);
  }

  const encodeParams = encodeParameters(types, values);

  const paramsHash = soliditySha3(encodeParams);

  // Ethereum signed message hash (EIP-191)
  const PREFIX = "\x19Ethereum Signed Message:\n32";
  const messageHash = hexToUint8Array(paramsHash);
  const prefixedMessage = Buffer.concat([
    Buffer.from(PREFIX),
    Buffer.from(messageHash),
  ]);
  const finalHash = keccak256(prefixedMessage);

  // Parse signature components
  const signatureBytes = hexToUint8Array(signature);
  const r = signatureBytes.slice(0, 32);
  const s = signatureBytes.slice(32, 64);
  const v = signatureBytes[64];

  // Convert v to recovery id (27/28 -> 0/1)
  const recoveryId = v - 27;
  if (recoveryId !== 0 && recoveryId !== 1) {
    throw new Error(`Invalid recovery id: ${recoveryId}`);
  }

  try {
    // Recover the public key
    const pubKey = secp256k1.ecdsaRecover(
      Buffer.concat([r, s]),
      recoveryId,
      Buffer.from(finalHash, "hex"),
      false
    );

    // Convert public key to address
    // The address is the last 20 bytes of the public key's keccak256 hash
    // It is generated from the uncompressed public key
    // We also have to remove the prefix 0x04 from the public key
    const pubKeyHash = keccak256(Buffer.from(pubKey.slice(1)));
    const address = "0x" + pubKeyHash.slice(-40);

    return address.toLowerCase() === originAddress.toLowerCase();
  } catch (error) {
    console.error("Signature recovery failed:", error);
    return false;
  }
}

// Web3.js adds 0x to the beginning of the hex string
function stringToHex(str) {
  return "0x" + Buffer.from(str, "utf8").toString("hex");
}

// Based on the Solidity ABI encoding we have the following definitions for encoding bytes32 and address
// For any ABI value X, we recursively define enc(X), depending on the type of X being
// bytes<M>: enc(X) is the sequence of bytes in X padded with trailing zero-bytes to a length of 32 bytes.
// address: as in the uint160 case
// uint<M>: enc(X) is the big-endian encoding of X, padded on the higher-order (left) side with zero-bytes such that the length is 32 bytes.
// https://docs.soliditylang.org/en/latest/abi-spec.html#formal-specification-of-the-encoding
function encodeParameters(types, values) {
  return (
    "0x" +
    types
      .map((type, index) => {
        if (type === "bytes32") {
          return values[index].replace(/^0x/, "").padEnd(64, "0");
        } else if (type === "address") {
          return values[index]
            .replace(/^0x/, "")
            .toLowerCase()
            .padStart(64, "0");
        } else {
          throw Error(
            `Expected type to be either bytes32 or address, instead received: ${type}`
          );
        }
      })
      .join("")
  );
}

// Will calculate the sha3 of given input parameters in the same way solidity would.
// This means arguments will be ABI converted and tightly packed before being hashed.
// String: HEX string with leading 0x is interpreted as bytes.
// https://web3js.readthedocs.io/en/v1.2.11/web3-utils.html#soliditysha3
function soliditySha3(encodeParams) {
  // If it's empty, return undefined to match Web3.js behavior
  if (!encodeParams || encodeParams === "0x") {
    return undefined;
  }
  const bytes = Buffer.from(encodeParams.replace("0x", ""), "hex");
  return "0x" + keccak256(bytes);
}

function hexToUint8Array(hex) {
  return new Uint8Array(
    hex.startsWith("0x")
      ? hex
          .slice(2)
          .match(/.{1,2}/g)
          .map((byte) => parseInt(byte, 16))
      : []
  );
}

module.exports = {
  verifyECDSASignature,
  stringToHex,
  encodeParameters,
  soliditySha3,
};
