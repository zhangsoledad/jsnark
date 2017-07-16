/*******************************************************************************
 * Author: zhiwei ning <rink1969@cryptape.com>
 *******************************************************************************/
package examples.gadgets;

import java.util.Arrays;
import java.math.BigInteger;

import util.Util;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;

public class Blake2bGadget extends Gadget {

	private static final long H[] = { 0xcbbb9d5dc1059ed8L, 0x629a292a367cd507L, 0x9159015a3070dd17L, 0x152fecd8f70e5939L, 0x67332667ffc00b31L, 0x8eb44a8768581511L,
			0xdb0c2e0d64f98fa7L, 0x47b5481dbefa4fa4L };

	// the key of blake2b in zcash "ZcashComputehSig"
	private static final long Key = new BigInteger("5a63617368436f6d7075746568536967", 16);
	private static final long KeyLenInBytes = 16;
	// for blake2b-256
	private static final long OutputLengthInBytes = 32;

	private Wire[] unpaddedInputs;

	private int bitwidthPerInputElement;
	private int totalLengthInBytes;

	private Wire[] preparedInputBits;
	private Wire[] output;

	public Blake2bGadget(Wire[] ins, int bitWidthPerInputElement, int totalLengthInBytes, boolean binaryOutput,
			boolean paddingRequired, String... desc) {

		super(desc);
		if (totalLengthInBytes * 8 > ins.length * bitWidthPerInputElement
				|| totalLengthInBytes * 8 < (ins.length - 1) * bitWidthPerInputElement) {
			throw new IllegalArgumentException("Inconsistent Length Information");
		}

		this.unpaddedInputs = ins;
		this.bitwidthPerInputElement = bitWidthPerInputElement;
		this.totalLengthInBytes = totalLengthInBytes;

		buildCircuit();

	}

	protected void buildCircuit() {
		Wire keyWire = generator.createConstantWire(Key);

		Wire[] outDigest = new Wire[8];
		Wire[] hWires = new Wire[H.length];
		for (int i = 0; i < H.length; i++) {
			hWires[i] = generator.createConstantWire(H[i]);
		}

		//h0 ← h0 xor 0x0101kknn
		//where kk is Key Length (in bytes)
        //nn is Desired Hash Length (in bytes)
		long tmp = 0x0101 * 0x10000 + KeyLen * 0x100 + OutputLengthInBytes;
		Wire tmpWire = generator.createConstantWire(tmp);
		hWires[0] = hWires[0].xorBitwise(tmpWire, 64);

		//Each time we Compress we record how many bytes have been compressed
		// cBytesCompressed ← 0
   		// cBytesRemaining  ← cbMessageLen
		long cBytesCompressed = 0;
		long cBytesRemaining = totalLengthInBytes;

		// pad with zeros to make key 128-bytes
		// then prepend it to the message M
		cBytesRemaining = cBytesRemaining + 128;
		preparedInputBits = generator.generateZeroWireArray(cBytesRemaining);
		Wire[] keyWireBytes = new WireArray(keyWire).getBits(bitwidthPerInputElement).asArray();
		System.arraycopy(keyWire, 0, preparedInputBits, 0, KeyLenInBytes);
		System.arraycopy(unpaddedInputs, 0, preparedInputBits, 128, totalLengthInBytes);

		// Compress whole 128-byte chunks of the message, except the last chunk
		long chunk_index = 0;
		while (cBytesRemaining > 128) {
			// chunk ← get next 128 bytes of message M
			Wire[] chunk = generator.generateZeroWireArray(128);
			System.arraycopy(preparedInputBits, chunk_index * 128, chunk, 0, 128);

			cBytesCompressed = cBytesCompressed + 128;
			cBytesRemaining = cBytesRemaining -128;
			chunk_index = chunk_index + 1;
			compress(hWires, chunk, cBytesCompressed, false);
		}

		// padding the last chunk
		Wire[] chunk = new Wire[128];
		for (int i = 0; i < 128; i++) {
			chunk[i] = generator.getZeroWire();
		}
		System.arraycopy(preparedInputBits, chunk_index * 128, chunk, 0, cBytesRemaining);
		cBytesCompressed = cBytesCompressed + cBytesRemaining;
		compress(hWires, chunk, cBytesCompressed, true);

		// first cbHashLen bytes of little endian state vector h
		// TODO
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

	private Wire compress(Wire[] h, Wire[] chunk, long t, boolean isLastChunk) {

	}

	/**
	 * outputs digest as 32-bit words
	 */
	@Override
	public Wire[] getOutputWires() {
		return output;
	}
}
