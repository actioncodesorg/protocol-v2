import {
  buildProtocolMeta,
  parseProtocolMeta,
  validateProtocolMetaFormat,
  SCHEME,
} from "../../src/utils/protocolMeta";
import { PROTOCOL_META_MAX_BYTES } from "../../src/constants";

describe("ProtocolMeta", () => {
  test("builds canonical string with ver,id,int and optional p", () => {
    const s = buildProtocolMeta({
      ver: 2,
      id: "abc123",
      int: "wallet:solana",
      p: { action: "pay-2usdc" },
    });
    expect(s).toBe(`${SCHEME}ver=2&id=abc123&int=wallet%3Asolana&p=%7B%22action%22%3A%22pay-2usdc%22%7D`);
  });

  test("parses canonical string and normalizes", () => {
    const input = `${SCHEME}ver=2&id=%20AbC%20123%20&int=wallet%3Asolana&p=%7B%22action%22%3A%22hello%20world%22%7D`;
    const fields = parseProtocolMeta(input);
    expect(fields.ver).toBe(2);
    expect(fields.id).toBe("AbC 123");
    expect(fields.int).toBe("wallet:solana");
    expect(fields.p).toEqual({ action: "hello world" });
  });

  test("rejects unknown keys", () => {
    const bad = `${SCHEME}ver=1&id=abc&int=x&x=1`;
    expect(() => parseProtocolMeta(bad)).toThrow(/unsupported keys/);
  });

  test("requires ver,id,int", () => {
    expect(() => parseProtocolMeta(`${SCHEME}ver=1&int=x`)).toThrow(
      /missing required/
    );
    expect(() => parseProtocolMeta(`${SCHEME}id=abc&int=x`)).toThrow(
      /missing required/
    );
    expect(() => parseProtocolMeta(`${SCHEME}ver=1&id=abc`)).toThrow(
      /missing required/
    );
  });

  test("enforces overall byte limit", () => {
    const big = "x".repeat(PROTOCOL_META_MAX_BYTES + 10);
    expect(() => buildProtocolMeta({ ver: 2, id: big, int: "x" })).toThrow(
      /exceeds/
    );
  });

  test("enforces params byte limit", () => {
    const p = "y".repeat(PROTOCOL_META_MAX_BYTES + 1);
    expect(() => buildProtocolMeta({ ver: 2, id: "a", int: "x", p: { action: p } })).toThrow(
      /params exceed/
    );
  });

  test("validateProtocolMetaFormat ok/fail", () => {
    const ok = `${SCHEME}ver=2&id=abc&int=me`;
    expect(validateProtocolMetaFormat(ok)).toEqual({ ok: true });
    const bad = `wrong:id=abc`;
    const res = validateProtocolMetaFormat(bad);
    expect(res.ok).toBe(false);
  });

  describe("iss field", () => {
    test("builds and parses with iss field when different from int", () => {
      const s = buildProtocolMeta({
        ver: 2,
        id: "abc123",
        int: "wallet:solana",
        iss: "issuer:solana",
      });
      expect(s).toBe(`${SCHEME}ver=2&id=abc123&int=wallet%3Asolana&iss=issuer%3Asolana`);
      
      const fields = parseProtocolMeta(s);
      expect(fields.ver).toBe(2);
      expect(fields.id).toBe("abc123");
      expect(fields.int).toBe("wallet:solana");
      expect(fields.iss).toBe("issuer:solana");
    });

    test("omits iss field when same as int", () => {
      const s = buildProtocolMeta({
        ver: 2,
        id: "abc123",
        int: "wallet:solana",
        iss: "wallet:solana", // same as int
      });
      // iss should not be present in the output
      expect(s).toBe(`${SCHEME}ver=2&id=abc123&int=wallet%3Asolana`);
      expect(s).not.toContain("iss=");
    });

    test("parses correctly when iss is omitted and defaults to int", () => {
      const input = `${SCHEME}ver=2&id=abc123&int=wallet%3Asolana`;
      const fields = parseProtocolMeta(input);
      expect(fields.ver).toBe(2);
      expect(fields.id).toBe("abc123");
      expect(fields.int).toBe("wallet:solana");
      expect(fields.iss).toBeUndefined();
    });

    test("normalizes iss field (trims whitespace)", () => {
      const input = `${SCHEME}ver=2&id=abc&int=wallet%3Asolana&iss=%20%20issuer%3Asolana%20%20`;
      const fields = parseProtocolMeta(input);
      expect(fields.iss).toBe("issuer:solana");
    });

    test("handles iss field with special characters", () => {
      const s = buildProtocolMeta({
        ver: 2,
        id: "abc123",
        int: "wallet:solana:addr1",
        iss: "issuer:solana:addr2",
      });
      expect(s).toContain("iss=issuer%3Asolana%3Aaddr2");
      
      const fields = parseProtocolMeta(s);
      expect(fields.iss).toBe("issuer:solana:addr2");
    });

    test("builds with iss and params", () => {
      const s = buildProtocolMeta({
        ver: 2,
        id: "abc123",
        int: "wallet:solana",
        iss: "issuer:solana",
        p: { action: "pay-2usdc" },
      });
      expect(s).toBe(
        `${SCHEME}ver=2&id=abc123&int=wallet%3Asolana&iss=issuer%3Asolana&p=%7B%22action%22%3A%22pay-2usdc%22%7D`
      );
      
      const fields = parseProtocolMeta(s);
      expect(fields.iss).toBe("issuer:solana");
      expect(fields.p).toEqual({ action: "pay-2usdc" });
    });

    test("enforces byte limit on iss field", () => {
      const bigIss = "x".repeat(PROTOCOL_META_MAX_BYTES + 1);
      expect(() =>
        buildProtocolMeta({ ver: 2, id: "abc", int: "wallet", iss: bigIss })
      ).toThrow(/exceeds/);
    });
  });
});
