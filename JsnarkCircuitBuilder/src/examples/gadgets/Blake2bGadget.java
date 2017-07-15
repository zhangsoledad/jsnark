/*******************************************************************************
 * Author: zhiwei ning <rink1969@cryptape.com>
 *******************************************************************************/
package examples.gadgets;

import java.util.Arrays;

import util.Util;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;

public class Blake2bGadget extends Gadget {

	private static final long H[] = { 0xcbbb9d5dc1059ed8L, 0x629a292a367cd507L, 0x9159015a3070dd17L, 0x152fecd8f70e5939L, 0x67332667ffc00b31L, 0x8eb44a8768581511L,
			0xdb0c2e0d64f98fa7L, 0x47b5481dbefa4fa4L };

	// the key of blake2b in zcash "ZcashComputehSig"
	private static final long Key = 0x5a63617368436f6d7075746568536967L;
	private static final long KeyLen = 16;

	private long cBytesCompressed = 0;
	private	long cBytesRemaining = 0;

	private Wire[] unpaddedInputs;

	private int bitwidthPerInputElement;
	private int totalLengthInBytes;

	private int numBlocks;
	private boolean binaryOutput;
	private boolean paddingRequired;

	private Wire[] preparedInputBits;
	private Wire[] output;

	public Blake2bGadget(Wire[] ins, int bitWidthPerInputElement, int totalLengthInBytes, boolean binaryOutput,
			boolean paddingRequired, String... desc) {

		super(desc);
		if (totalLengthInBytes * 8 > ins.length * bitWidthPerInputElement
				|| totalLengthInBytes * 8 < (ins.length - 1) * bitWidthPerInputElement) {
			throw new IllegalArgumentException("Inconsistent Length Information");
		}

		if (!paddingRequired && totalLengthInBytes % 64 != 0
				&& ins.length * bitWidthPerInputElement != totalLengthInBytes) {
			throw new IllegalArgumentException("When padding is not forced, totalLengthInBytes % 64 must be zero.");
		}

		this.unpaddedInputs = ins;
		this.bitwidthPerInputElement = bitWidthPerInputElement;
		this.totalLengthInBytes = totalLengthInBytes;
		this.binaryOutput = binaryOutput;
		this.paddingRequired = paddingRequired;

		buildCircuit();

	}

	protected void buildCircuit() {
		Wire[] outDigest = new Wire[8];
		Wire[] hWires = new Wire[H.length];
		for (int i = 0; i < H.length; i++) {
			hWires[i] = generator.createConstantWire(H[i]);
		}

		//h0 ← h0 xor 0x0101kknn
		//where kk is Key Length (in bytes)
        //nn is Desired Hash Length (in bytes)
		long kk = KeyLen;
		long nn = 32;
		long tmp = 0x01011020L;
		Wire tmpWire = generator.createConstantWire(tmp);
		hWires[0] = hWires[0].xorBitwise(tmpWire, 128);

		//Each time we Compress we record how many bytes have been compressed
		// cBytesCompressed ← 0
   		// cBytesRemaining  ← cbMessageLen
		cBytesCompressed = 0;
		cBytesRemaining = totalLengthInBytes;

		// padding key to 128 bits
		// then prepend it to the message M
		cBytesRemaining = cBytesRemaining + 128;
		Wire keyWire = generator.createConstantWire(Key);
		preparedInputBits = new Wire[cBytesRemaining];
		Arrays.fill(preparedInputBits, generator.getZeroWire());
		System.arraycopy(keyWire, 0, preparedInputBits, 128-KeyLen, KeyLen);
		System.arraycopy(unpaddedInputs, 0, preparedInputBits, 128, totalLengthInBytes);

		// Compress whole 128-byte chunks of the message, except the last chunk
		long remainLen = cBytesRemaining % 128;
		long chunk_num = cBytesRemaining / 128;
		long chunk_index = 0;
		while (cBytesRemaining > 128) {
			// chunk ← get next 128 bytes of message M
			Wire[] chunk = new Wire[128];
			System.arraycopy(preparedInputBits, chunk_index * 128, chunk, 0, 128);

			cBytesCompressed = cBytesCompressed + 128;
			cBytesRemaining = cBytesRemaining -128;
			chunk_index = chunk_index + 1;
			compress(hWires, chunk, false);
		}

		// padding the last chunk
		Wire[] chunk = new Wire[128];
		for (int i = 0; i < 128; i++) {
			chunk[i] = generator.getZeroWire();
		}
		System.arraycopy(preparedInputBits, chunk_num * 128, chunk, 0, remainLen);
		cBytesCompressed = cBytesCompressed + cBytesRemaining;
		compress(hWires, chunk, true);

		// first cbHashLen bytes of little endian state vector h
		outDigest[0] = hWires[0];
		outDigest[1] = hWires[1];
		outDigest[2] = hWires[2];
		outDigest[3] = hWires[3];
		outDigest[4] = hWires[4];
		outDigest[5] = hWires[5];
		outDigest[6] = hWires[6];
		outDigest[7] = hWires[7];

		output = new Wire[8 * 32];
		for (int i = 0; i < 8; i++) {
			Wire[] bits = outDigest[i].getBitWires(32).asArray();
			for (int j = 0; j < 32; j++) {
				output[j + i * 32] = bits[j];
			}
		}
	}

	private Wire compress(Wire[] h, Wire[] chunk, boolean isLastChunk) {
		long t = cBytesCompressed;

	}

	private Wire computeMaj(Wire a, Wire b, Wire c, int numBits) {

		Wire[] result = new Wire[numBits];
		Wire[] aBits = a.getBitWires(numBits).asArray();
		Wire[] bBits = b.getBitWires(numBits).asArray();
		Wire[] cBits = c.getBitWires(numBits).asArray();

		for (int i = 0; i < numBits; i++) {
			Wire t1 = aBits[i].mul(bBits[i]);
			Wire t2 = aBits[i].add(bBits[i]).add(t1.mul(-2));
			result[i] = t1.add(cBits[i].mul(t2));
		}
		return new WireArray(result).packAsBits();
	}

	private Wire computeCh(Wire a, Wire b, Wire c, int numBits) {
		Wire[] result = new Wire[numBits];

		Wire[] aBits = a.getBitWires(numBits).asArray();
		Wire[] bBits = b.getBitWires(numBits).asArray();
		Wire[] cBits = c.getBitWires(numBits).asArray();

		for (int i = 0; i < numBits; i++) {
			Wire t1 = bBits[i].sub(cBits[i]);
			Wire t2 = t1.mul(aBits[i]);
			result[i] = t2.add(cBits[i]);
		}
		return new WireArray(result).packAsBits();
	}

	/**
	 * outputs digest as 32-bit words
	 */
	@Override
	public Wire[] getOutputWires() {
		return output;
	}
}
