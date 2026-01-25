"""
VFEdit Clone - Telephony Audio Converter & Editor
A Python implementation of VFEdit functionality for converting and editing
voice files compatible with legacy computer telephony systems.

Supports: WAV, PCM, Mu-law, A-law, ADPCM (IMA/DVI), and raw audio formats
Compatible with: Dialogic, NMS, Intervoice, and other CTI platforms

Run in Google Colab or any Python environment.
"""

import numpy as np
import struct
import wave
import io
from typing import Union, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

# ============================================================================
# AUDIO FORMAT DEFINITIONS
# ============================================================================

class AudioFormat(Enum):
    PCM_8 = "pcm_8"           # 8-bit unsigned PCM
    PCM_16 = "pcm_16"         # 16-bit signed PCM (standard)
    MULAW = "mulaw"           # Mu-law (G.711 μ-law)
    ALAW = "alaw"             # A-law (G.711 A-law)
    ADPCM_IMA = "adpcm_ima"   # IMA/DVI ADPCM (4-bit)
    ADPCM_MS = "adpcm_ms"     # Microsoft ADPCM
    VOX = "vox"               # Dialogic VOX ADPCM

@dataclass
class AudioData:
    """Container for audio data with metadata"""
    samples: np.ndarray       # Audio samples as float32 (-1.0 to 1.0)
    sample_rate: int          # Sample rate in Hz
    channels: int = 1         # Number of channels

    @property
    def duration(self) -> float:
        """Duration in seconds"""
        return len(self.samples) / self.sample_rate

    @property
    def num_samples(self) -> int:
        return len(self.samples)

# ============================================================================
# MU-LAW CODEC (G.711 μ-law) - Used by North American telephony
# ============================================================================

class MuLawCodec:
    """
    Mu-law companding codec (ITU-T G.711)
    Standard for North American and Japanese telephony systems
    Compresses 16-bit PCM to 8-bit mu-law
    """

    MULAW_MAX = 0x1FFF
    MULAW_BIAS = 33

    # Mu-law to linear conversion table
    MULAW_TO_LINEAR = np.array([
        -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956,
        -23932, -22908, -21884, -20860, -19836, -18812, -17788, -16764,
        -15996, -15484, -14972, -14460, -13948, -13436, -12924, -12412,
        -11900, -11388, -10876, -10364, -9852, -9340, -8828, -8316,
        -7932, -7676, -7420, -7164, -6908, -6652, -6396, -6140,
        -5884, -5628, -5372, -5116, -4860, -4604, -4348, -4092,
        -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004,
        -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
        -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436,
        -1372, -1308, -1244, -1180, -1116, -1052, -988, -924,
        -876, -844, -812, -780, -748, -716, -684, -652,
        -620, -588, -556, -524, -492, -460, -428, -396,
        -372, -356, -340, -324, -308, -292, -276, -260,
        -244, -228, -212, -196, -180, -164, -148, -132,
        -120, -112, -104, -96, -88, -80, -72, -64,
        -56, -48, -40, -32, -24, -16, -8, 0,
        32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956,
        23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764,
        15996, 15484, 14972, 14460, 13948, 13436, 12924, 12412,
        11900, 11388, 10876, 10364, 9852, 9340, 8828, 8316,
        7932, 7676, 7420, 7164, 6908, 6652, 6396, 6140,
        5884, 5628, 5372, 5116, 4860, 4604, 4348, 4092,
        3900, 3772, 3644, 3516, 3388, 3260, 3132, 3004,
        2876, 2748, 2620, 2492, 2364, 2236, 2108, 1980,
        1884, 1820, 1756, 1692, 1628, 1564, 1500, 1436,
        1372, 1308, 1244, 1180, 1116, 1052, 988, 924,
        876, 844, 812, 780, 748, 716, 684, 652,
        620, 588, 556, 524, 492, 460, 428, 396,
        372, 356, 340, 324, 308, 292, 276, 260,
        244, 228, 212, 196, 180, 164, 148, 132,
        120, 112, 104, 96, 88, 80, 72, 64,
        56, 48, 40, 32, 24, 16, 8, 0
    ], dtype=np.int16)

    @staticmethod
    def encode(pcm_samples: np.ndarray) -> np.ndarray:
        """Encode 16-bit PCM samples to 8-bit mu-law"""
        # Convert to int16 if needed
        if pcm_samples.dtype == np.float32 or pcm_samples.dtype == np.float64:
            pcm_samples = (pcm_samples * 32767).astype(np.int16)

        # Mu-law encoding algorithm
        sign = (pcm_samples >> 8) & 0x80
        sample = np.abs(pcm_samples)
        sample = np.clip(sample + MuLawCodec.MULAW_BIAS, 0, MuLawCodec.MULAW_MAX)

        # Find segment and quantization
        exponent = np.zeros(len(sample), dtype=np.uint8)
        mantissa = np.zeros(len(sample), dtype=np.uint8)

        for i in range(8):
            mask = sample >= (1 << (i + 7))
            exponent[mask] = i

        shifted = (sample >> (exponent + 3)).astype(np.uint8)
        mantissa = shifted & 0x0F

        mulaw = ~(sign | (exponent << 4) | mantissa)
        return mulaw.astype(np.uint8)

    @staticmethod
    def decode(mulaw_samples: np.ndarray) -> np.ndarray:
        """Decode 8-bit mu-law samples to 16-bit PCM"""
        return MuLawCodec.MULAW_TO_LINEAR[mulaw_samples.astype(np.uint8)]

# ============================================================================
# A-LAW CODEC (G.711 A-law) - Used by European telephony
# ============================================================================

class ALawCodec:
    """
    A-law companding codec (ITU-T G.711)
    Standard for European telephony systems
    Compresses 16-bit PCM to 8-bit A-law
    """

    # A-law to linear conversion table
    ALAW_TO_LINEAR = np.array([
        -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736,
        -7552, -7296, -8064, -7808, -6528, -6272, -7040, -6784,
        -2752, -2624, -3008, -2880, -2240, -2112, -2496, -2368,
        -3776, -3648, -4032, -3904, -3264, -3136, -3520, -3392,
        -22016, -20992, -24064, -23040, -17920, -16896, -19968, -18944,
        -30208, -29184, -32256, -31232, -26112, -25088, -28160, -27136,
        -11008, -10496, -12032, -11520, -8960, -8448, -9984, -9472,
        -15104, -14592, -16128, -15616, -13056, -12544, -14080, -13568,
        -344, -328, -376, -360, -280, -264, -312, -296,
        -472, -456, -504, -488, -408, -392, -440, -424,
        -88, -72, -120, -104, -24, -8, -56, -40,
        -216, -200, -248, -232, -152, -136, -184, -168,
        -1376, -1312, -1504, -1440, -1120, -1056, -1248, -1184,
        -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696,
        -688, -656, -752, -720, -560, -528, -624, -592,
        -944, -912, -1008, -976, -816, -784, -880, -848,
        5504, 5248, 6016, 5760, 4480, 4224, 4992, 4736,
        7552, 7296, 8064, 7808, 6528, 6272, 7040, 6784,
        2752, 2624, 3008, 2880, 2240, 2112, 2496, 2368,
        3776, 3648, 4032, 3904, 3264, 3136, 3520, 3392,
        22016, 20992, 24064, 23040, 17920, 16896, 19968, 18944,
        30208, 29184, 32256, 31232, 26112, 25088, 28160, 27136,
        11008, 10496, 12032, 11520, 8960, 8448, 9984, 9472,
        15104, 14592, 16128, 15616, 13056, 12544, 14080, 13568,
        344, 328, 376, 360, 280, 264, 312, 296,
        472, 456, 504, 488, 408, 392, 440, 424,
        88, 72, 120, 104, 24, 8, 56, 40,
        216, 200, 248, 232, 152, 136, 184, 168,
        1376, 1312, 1504, 1440, 1120, 1056, 1248, 1184,
        1888, 1824, 2016, 1952, 1632, 1568, 1760, 1696,
        688, 656, 752, 720, 560, 528, 624, 592,
        944, 912, 1008, 976, 816, 784, 880, 848
    ], dtype=np.int16)

    @staticmethod
    def encode(pcm_samples: np.ndarray) -> np.ndarray:
        """Encode 16-bit PCM samples to 8-bit A-law"""
        if pcm_samples.dtype == np.float32 or pcm_samples.dtype == np.float64:
            pcm_samples = (pcm_samples * 32767).astype(np.int16)

        sign = np.where(pcm_samples >= 0, 0xD5, 0x55)
        sample = np.abs(pcm_samples)

        # Find exponent and mantissa
        exponent = np.ones(len(sample), dtype=np.uint8)
        for i in range(7, 0, -1):
            mask = sample >= (1 << (i + 4))
            exponent[mask] = np.maximum(exponent[mask], i)

        mantissa = np.where(
            exponent == 0,
            (sample >> 4) & 0x0F,
            (sample >> (exponent + 3)) & 0x0F
        ).astype(np.uint8)

        alaw = (sign ^ ((exponent << 4) | mantissa)).astype(np.uint8)
        return alaw

    @staticmethod
    def decode(alaw_samples: np.ndarray) -> np.ndarray:
        """Decode 8-bit A-law samples to 16-bit PCM"""
        return ALawCodec.ALAW_TO_LINEAR[alaw_samples.astype(np.uint8)]

# ============================================================================
# IMA/DVI ADPCM CODEC - Used by Dialogic and many telephony systems
# ============================================================================

class IMAAdpcmCodec:
    """
    IMA/DVI ADPCM codec (4-bit)
    Widely used in telephony, including Dialogic VOX format
    Compresses 16-bit PCM to 4-bit ADPCM (2:1 compression)
    """

    # Step size index table
    INDEX_TABLE = np.array([
        -1, -1, -1, -1, 2, 4, 6, 8,
        -1, -1, -1, -1, 2, 4, 6, 8
    ], dtype=np.int8)

    # Step size table
    STEP_TABLE = np.array([
        7, 8, 9, 10, 11, 12, 13, 14, 16, 17,
        19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
        50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
        130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
        337, 371, 408, 449, 494, 544, 598, 658, 724, 796,
        876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
        2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
        5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
        15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767
    ], dtype=np.int16)

    @staticmethod
    def encode(pcm_samples: np.ndarray) -> bytes:
        """Encode 16-bit PCM to IMA ADPCM"""
        if pcm_samples.dtype == np.float32 or pcm_samples.dtype == np.float64:
            pcm_samples = (pcm_samples * 32767).astype(np.int16)

        predicted = 0
        index = 0
        output = []
        nibble_buffer = []

        for sample in pcm_samples:
            sample = int(sample)
            step = IMAAdpcmCodec.STEP_TABLE[index]

            # Calculate difference
            diff = sample - predicted

            # Encode nibble
            nibble = 0
            if diff < 0:
                nibble = 8
                diff = -diff

            if diff >= step:
                nibble |= 4
                diff -= step
            step >>= 1
            if diff >= step:
                nibble |= 2
                diff -= step
            step >>= 1
            if diff >= step:
                nibble |= 1

            # Decode to update predictor
            step = IMAAdpcmCodec.STEP_TABLE[index]
            diff = step >> 3
            if nibble & 4:
                diff += step
            if nibble & 2:
                diff += step >> 1
            if nibble & 1:
                diff += step >> 2

            if nibble & 8:
                predicted -= diff
            else:
                predicted += diff

            predicted = max(-32768, min(32767, predicted))

            # Update index
            index += IMAAdpcmCodec.INDEX_TABLE[nibble]
            index = max(0, min(88, index))

            nibble_buffer.append(nibble)
            if len(nibble_buffer) == 2:
                byte = (nibble_buffer[1] << 4) | nibble_buffer[0]
                output.append(byte)
                nibble_buffer = []

        # Handle odd sample count
        if nibble_buffer:
            output.append(nibble_buffer[0])

        return bytes(output)

    @staticmethod
    def decode(adpcm_data: bytes) -> np.ndarray:
        """Decode IMA ADPCM to 16-bit PCM"""
        predicted = 0
        index = 0
        output = []

        for byte in adpcm_data:
            for nibble in [byte & 0x0F, (byte >> 4) & 0x0F]:
                step = IMAAdpcmCodec.STEP_TABLE[index]

                diff = step >> 3
                if nibble & 4:
                    diff += step
                if nibble & 2:
                    diff += step >> 1
                if nibble & 1:
                    diff += step >> 2

                if nibble & 8:
                    predicted -= diff
                else:
                    predicted += diff

                predicted = max(-32768, min(32767, predicted))
                output.append(predicted)

                index += IMAAdpcmCodec.INDEX_TABLE[nibble]
                index = max(0, min(88, index))

        return np.array(output, dtype=np.int16)

# ============================================================================
# DIALOGIC VOX FORMAT - Common telephony format
# ============================================================================

class DialogicVox:
    """
    Dialogic VOX format handler
    Uses OKI/Dialogic ADPCM (similar to IMA but with different tables)
    Standard: 8000 Hz, mono, 4-bit ADPCM
    """

    # Dialogic/OKI ADPCM step table (differs from IMA)
    STEP_TABLE = np.array([
        16, 17, 19, 21, 23, 25, 28, 31, 34, 37,
        41, 45, 50, 55, 60, 66, 73, 80, 88, 97,
        107, 118, 130, 143, 157, 173, 190, 209, 230, 253,
        279, 307, 337, 371, 408, 449, 494, 544, 598, 658,
        724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707,
        1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428,
        4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487,
        12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794,
        32767
    ], dtype=np.int32)

    INDEX_TABLE = np.array([-1, -1, -1, -1, 2, 4, 6, 8], dtype=np.int8)

    @staticmethod
    def decode(vox_data: bytes) -> np.ndarray:
        """Decode Dialogic VOX to 16-bit PCM"""
        predicted = 0
        index = 0
        output = []

        for byte in vox_data:
            # VOX stores high nibble first
            for nibble in [(byte >> 4) & 0x0F, byte & 0x0F]:
                step = DialogicVox.STEP_TABLE[min(index, len(DialogicVox.STEP_TABLE)-1)]

                diff = 0
                if nibble & 4:
                    diff += step
                if nibble & 2:
                    diff += step >> 1
                if nibble & 1:
                    diff += step >> 2
                diff += step >> 3

                if nibble & 8:
                    predicted -= diff
                else:
                    predicted += diff

                predicted = max(-32768, min(32767, predicted))
                output.append(predicted)

                index += DialogicVox.INDEX_TABLE[nibble & 0x07]
                index = max(0, min(len(DialogicVox.STEP_TABLE)-1, index))

        return np.array(output, dtype=np.int16)

    @staticmethod
    def encode(pcm_samples: np.ndarray) -> bytes:
        """Encode 16-bit PCM to Dialogic VOX"""
        if pcm_samples.dtype == np.float32 or pcm_samples.dtype == np.float64:
            pcm_samples = (pcm_samples * 32767).astype(np.int16)

        predicted = 0
        index = 0
        output = []
        nibbles = []

        for sample in pcm_samples:
            sample = int(sample)
            step = DialogicVox.STEP_TABLE[min(index, len(DialogicVox.STEP_TABLE)-1)]

            diff = sample - predicted
            nibble = 0

            if diff < 0:
                nibble = 8
                diff = -diff

            if diff >= step:
                nibble |= 4
                diff -= step
            if diff >= step >> 1:
                nibble |= 2
                diff -= step >> 1
            if diff >= step >> 2:
                nibble |= 1

            # Update predictor
            step = DialogicVox.STEP_TABLE[min(index, len(DialogicVox.STEP_TABLE)-1)]
            diff = 0
            if nibble & 4:
                diff += step
            if nibble & 2:
                diff += step >> 1
            if nibble & 1:
                diff += step >> 2
            diff += step >> 3

            if nibble & 8:
                predicted -= diff
            else:
                predicted += diff
            predicted = max(-32768, min(32767, predicted))

            index += DialogicVox.INDEX_TABLE[nibble & 0x07]
            index = max(0, min(len(DialogicVox.STEP_TABLE)-1, index))

            nibbles.append(nibble)
            if len(nibbles) == 2:
                # VOX: high nibble first
                output.append((nibbles[0] << 4) | nibbles[1])
                nibbles = []

        if nibbles:
            output.append(nibbles[0] << 4)

        return bytes(output)

# ============================================================================
# FILE I/O HANDLERS
# ============================================================================

class AudioFileIO:
    """
    Audio file reader/writer supporting multiple telephony formats
    """

    @staticmethod
    def read_wav(filepath: str) -> AudioData:
        """Read a WAV file"""
        with wave.open(filepath, 'rb') as wav:
            n_channels = wav.getnchannels()
            sample_width = wav.getsampwidth()
            sample_rate = wav.getframerate()
            n_frames = wav.getnframes()

            raw_data = wav.readframes(n_frames)

            if sample_width == 1:
                # 8-bit unsigned
                samples = np.frombuffer(raw_data, dtype=np.uint8)
                samples = (samples.astype(np.float32) - 128) / 128
            elif sample_width == 2:
                # 16-bit signed
                samples = np.frombuffer(raw_data, dtype=np.int16)
                samples = samples.astype(np.float32) / 32768
            else:
                raise ValueError(f"Unsupported sample width: {sample_width}")

            # Convert to mono if stereo
            if n_channels == 2:
                samples = samples.reshape(-1, 2).mean(axis=1)
                n_channels = 1

            return AudioData(samples, sample_rate, n_channels)

    @staticmethod
    def write_wav(filepath: str, audio: AudioData, sample_width: int = 2):
        """Write a WAV file"""
        with wave.open(filepath, 'wb') as wav:
            wav.setnchannels(audio.channels)
            wav.setsampwidth(sample_width)
            wav.setframerate(audio.sample_rate)

            if sample_width == 1:
                samples = ((audio.samples * 128) + 128).astype(np.uint8)
            else:
                samples = (audio.samples * 32767).astype(np.int16)

            wav.writeframes(samples.tobytes())

    @staticmethod
    def read_raw(filepath: str, format: AudioFormat, sample_rate: int = 8000) -> AudioData:
        """Read raw audio file in specified format"""
        with open(filepath, 'rb') as f:
            raw_data = f.read()

        if format == AudioFormat.PCM_8:
            samples = np.frombuffer(raw_data, dtype=np.uint8)
            samples = (samples.astype(np.float32) - 128) / 128
        elif format == AudioFormat.PCM_16:
            samples = np.frombuffer(raw_data, dtype=np.int16)
            samples = samples.astype(np.float32) / 32768
        elif format == AudioFormat.MULAW:
            mulaw_samples = np.frombuffer(raw_data, dtype=np.uint8)
            pcm = MuLawCodec.decode(mulaw_samples)
            samples = pcm.astype(np.float32) / 32768
        elif format == AudioFormat.ALAW:
            alaw_samples = np.frombuffer(raw_data, dtype=np.uint8)
            pcm = ALawCodec.decode(alaw_samples)
            samples = pcm.astype(np.float32) / 32768
        elif format == AudioFormat.ADPCM_IMA:
            pcm = IMAAdpcmCodec.decode(raw_data)
            samples = pcm.astype(np.float32) / 32768
        elif format == AudioFormat.VOX:
            pcm = DialogicVox.decode(raw_data)
            samples = pcm.astype(np.float32) / 32768
        else:
            raise ValueError(f"Unsupported format: {format}")

        return AudioData(samples, sample_rate)

    @staticmethod
    def write_raw(filepath: str, audio: AudioData, format: AudioFormat):
        """Write raw audio file in specified format"""
        if format == AudioFormat.PCM_8:
            samples = ((audio.samples * 128) + 128).astype(np.uint8)
            data = samples.tobytes()
        elif format == AudioFormat.PCM_16:
            samples = (audio.samples * 32767).astype(np.int16)
            data = samples.tobytes()
        elif format == AudioFormat.MULAW:
            data = MuLawCodec.encode(audio.samples).tobytes()
        elif format == AudioFormat.ALAW:
            data = ALawCodec.encode(audio.samples).tobytes()
        elif format == AudioFormat.ADPCM_IMA:
            data = IMAAdpcmCodec.encode(audio.samples)
        elif format == AudioFormat.VOX:
            data = DialogicVox.encode(audio.samples)
        else:
            raise ValueError(f"Unsupported format: {format}")

        with open(filepath, 'wb') as f:
            f.write(data)

# ============================================================================
# AUDIO PROCESSING / EDITING FUNCTIONS
# ============================================================================

class AudioProcessor:
    """Audio editing and processing functions"""

    @staticmethod
    def normalize(audio: AudioData, target_db: float = -3.0) -> AudioData:
        """Normalize audio to target dB level"""
        max_val = np.max(np.abs(audio.samples))
        if max_val == 0:
            return audio

        target_linear = 10 ** (target_db / 20)
        gain = target_linear / max_val

        return AudioData(
            audio.samples * gain,
            audio.sample_rate,
            audio.channels
        )

    @staticmethod
    def trim_silence(audio: AudioData, threshold_db: float = -40.0,
                     min_silence_ms: int = 100) -> AudioData:
        """Trim silence from beginning and end of audio"""
        threshold = 10 ** (threshold_db / 20)
        min_samples = int(min_silence_ms * audio.sample_rate / 1000)

        # Find start
        start = 0
        for i in range(len(audio.samples)):
            if abs(audio.samples[i]) > threshold:
                start = max(0, i - min_samples)
                break

        # Find end
        end = len(audio.samples)
        for i in range(len(audio.samples) - 1, -1, -1):
            if abs(audio.samples[i]) > threshold:
                end = min(len(audio.samples), i + min_samples)
                break

        return AudioData(
            audio.samples[start:end].copy(),
            audio.sample_rate,
            audio.channels
        )

    @staticmethod
    def resample(audio: AudioData, target_rate: int) -> AudioData:
        """Resample audio to target sample rate using linear interpolation"""
        if audio.sample_rate == target_rate:
            return audio

        ratio = target_rate / audio.sample_rate
        new_length = int(len(audio.samples) * ratio)

        # Linear interpolation
        old_indices = np.arange(len(audio.samples))
        new_indices = np.linspace(0, len(audio.samples) - 1, new_length)
        new_samples = np.interp(new_indices, old_indices, audio.samples)

        return AudioData(
            new_samples.astype(np.float32),
            target_rate,
            audio.channels
        )

    @staticmethod
    def concatenate(audio_list: list) -> AudioData:
        """Concatenate multiple audio segments"""
        if not audio_list:
            raise ValueError("Empty audio list")

        # Resample all to first audio's sample rate
        target_rate = audio_list[0].sample_rate
        resampled = [
            AudioProcessor.resample(a, target_rate) if a.sample_rate != target_rate else a
            for a in audio_list
        ]

        combined = np.concatenate([a.samples for a in resampled])
        return AudioData(combined, target_rate)

    @staticmethod
    def trim(audio: AudioData, start_ms: float, end_ms: float) -> AudioData:
        """Extract a portion of audio between start and end times (in milliseconds)"""
        start_sample = int(start_ms * audio.sample_rate / 1000)
        end_sample = int(end_ms * audio.sample_rate / 1000)

        start_sample = max(0, start_sample)
        end_sample = min(len(audio.samples), end_sample)

        return AudioData(
            audio.samples[start_sample:end_sample].copy(),
            audio.sample_rate,
            audio.channels
        )

    @staticmethod
    def fade_in(audio: AudioData, duration_ms: float) -> AudioData:
        """Apply fade-in effect"""
        fade_samples = int(duration_ms * audio.sample_rate / 1000)
        fade_samples = min(fade_samples, len(audio.samples))

        samples = audio.samples.copy()
        fade_curve = np.linspace(0, 1, fade_samples)
        samples[:fade_samples] *= fade_curve

        return AudioData(samples, audio.sample_rate, audio.channels)

    @staticmethod
    def fade_out(audio: AudioData, duration_ms: float) -> AudioData:
        """Apply fade-out effect"""
        fade_samples = int(duration_ms * audio.sample_rate / 1000)
        fade_samples = min(fade_samples, len(audio.samples))

        samples = audio.samples.copy()
        fade_curve = np.linspace(1, 0, fade_samples)
        samples[-fade_samples:] *= fade_curve

        return AudioData(samples, audio.sample_rate, audio.channels)

    @staticmethod
    def amplify(audio: AudioData, gain_db: float) -> AudioData:
        """Amplify or attenuate audio by specified dB"""
        gain = 10 ** (gain_db / 20)
        samples = np.clip(audio.samples * gain, -1.0, 1.0)
        return AudioData(samples, audio.sample_rate, audio.channels)

    @staticmethod
    def insert_silence(audio: AudioData, position_ms: float, duration_ms: float) -> AudioData:
        """Insert silence at specified position"""
        pos_sample = int(position_ms * audio.sample_rate / 1000)
        silence_samples = int(duration_ms * audio.sample_rate / 1000)

        silence = np.zeros(silence_samples, dtype=np.float32)
        samples = np.concatenate([
            audio.samples[:pos_sample],
            silence,
            audio.samples[pos_sample:]
        ])

        return AudioData(samples, audio.sample_rate, audio.channels)

    @staticmethod
    def reverse(audio: AudioData) -> AudioData:
        """Reverse the audio"""
        return AudioData(
            audio.samples[::-1].copy(),
            audio.sample_rate,
            audio.channels
        )

# ============================================================================
# FORMAT CONVERTER - Main conversion interface
# ============================================================================

class VFEditConverter:
    """
    Main converter class - converts between telephony audio formats
    Replicates core VFEdit functionality
    """

    TELEPHONY_RATE = 8000  # Standard telephony sample rate

    @staticmethod
    def convert(input_path: str, output_path: str,
                input_format: Optional[AudioFormat] = None,
                output_format: AudioFormat = AudioFormat.PCM_16,
                input_rate: int = 8000,
                output_rate: int = 8000) -> AudioData:
        """
        Convert audio file between formats

        Args:
            input_path: Input file path
            output_path: Output file path
            input_format: Input format (auto-detected from extension if None)
            output_format: Output format
            input_rate: Input sample rate (for raw files)
            output_rate: Output sample rate

        Returns:
            Converted AudioData
        """
        # Auto-detect input format from extension
        if input_format is None:
            ext = input_path.lower().split('.')[-1]
            format_map = {
                'wav': None,  # WAV has header
                'vox': AudioFormat.VOX,
                'raw': AudioFormat.PCM_16,
                'pcm': AudioFormat.PCM_16,
                'ul': AudioFormat.MULAW,
                'ulaw': AudioFormat.MULAW,
                'al': AudioFormat.ALAW,
                'alaw': AudioFormat.ALAW,
                'ima': AudioFormat.ADPCM_IMA,
                'adpcm': AudioFormat.ADPCM_IMA,
            }
            input_format = format_map.get(ext)

        # Read input
        if input_path.lower().endswith('.wav'):
            audio = AudioFileIO.read_wav(input_path)
        else:
            audio = AudioFileIO.read_raw(input_path, input_format, input_rate)

        # Resample if needed
        if audio.sample_rate != output_rate:
            audio = AudioProcessor.resample(audio, output_rate)

        # Write output
        if output_path.lower().endswith('.wav'):
            AudioFileIO.write_wav(output_path, audio)
        else:
            AudioFileIO.write_raw(output_path, audio, output_format)

        return audio

    @staticmethod
    def convert_bytes(input_data: bytes,
                      input_format: AudioFormat,
                      output_format: AudioFormat,
                      sample_rate: int = 8000) -> bytes:
        """
        Convert audio data between formats (in-memory)

        Args:
            input_data: Input audio bytes
            input_format: Input format
            output_format: Output format
            sample_rate: Sample rate

        Returns:
            Converted audio bytes
        """
        # Decode input to PCM
        if input_format == AudioFormat.PCM_16:
            pcm = np.frombuffer(input_data, dtype=np.int16)
        elif input_format == AudioFormat.PCM_8:
            samples = np.frombuffer(input_data, dtype=np.uint8)
            pcm = ((samples.astype(np.int16) - 128) * 256)
        elif input_format == AudioFormat.MULAW:
            pcm = MuLawCodec.decode(np.frombuffer(input_data, dtype=np.uint8))
        elif input_format == AudioFormat.ALAW:
            pcm = ALawCodec.decode(np.frombuffer(input_data, dtype=np.uint8))
        elif input_format == AudioFormat.ADPCM_IMA:
            pcm = IMAAdpcmCodec.decode(input_data)
        elif input_format == AudioFormat.VOX:
            pcm = DialogicVox.decode(input_data)
        else:
            raise ValueError(f"Unsupported input format: {input_format}")

        # Convert to float for processing
        samples = pcm.astype(np.float32) / 32768

        # Encode output
        if output_format == AudioFormat.PCM_16:
            return (samples * 32767).astype(np.int16).tobytes()
        elif output_format == AudioFormat.PCM_8:
            return ((samples * 128) + 128).astype(np.uint8).tobytes()
        elif output_format == AudioFormat.MULAW:
            return MuLawCodec.encode(samples).tobytes()
        elif output_format == AudioFormat.ALAW:
            return ALawCodec.encode(samples).tobytes()
        elif output_format == AudioFormat.ADPCM_IMA:
            return IMAAdpcmCodec.encode(samples)
        elif output_format == AudioFormat.VOX:
            return DialogicVox.encode(samples)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

# ============================================================================
# INTERACTIVE INTERFACE FOR GOOGLE COLAB
# ============================================================================

def create_test_tone(frequency: float = 440.0, duration: float = 1.0,
                     sample_rate: int = 8000) -> AudioData:
    """Create a test sine wave tone"""
    t = np.linspace(0, duration, int(sample_rate * duration), dtype=np.float32)
    samples = np.sin(2 * np.pi * frequency * t) * 0.5
    return AudioData(samples, sample_rate)

def demo():
    """Demonstration of VFEdit Clone functionality"""
    print("=" * 60)
    print("VFEdit Clone - Telephony Audio Converter Demo")
    print("=" * 60)

    # Create test tone
    print("\n1. Creating test tone (440 Hz, 1 second)...")
    audio = create_test_tone(440, 1.0, 8000)
    print(f"   Duration: {audio.duration:.2f}s, Samples: {audio.num_samples}")

    # Test Mu-law encoding/decoding
    print("\n2. Testing Mu-law codec...")
    pcm_samples = (audio.samples * 32767).astype(np.int16)
    mulaw_encoded = MuLawCodec.encode(pcm_samples)
    mulaw_decoded = MuLawCodec.decode(mulaw_encoded)
    error = np.mean(np.abs(pcm_samples - mulaw_decoded))
    print(f"   Mu-law compression: {len(pcm_samples)*2} bytes -> {len(mulaw_encoded)} bytes")
    print(f"   Average reconstruction error: {error:.2f}")

    # Test A-law encoding/decoding
    print("\n3. Testing A-law codec...")
    alaw_encoded = ALawCodec.encode(pcm_samples)
    alaw_decoded = ALawCodec.decode(alaw_encoded)
    error = np.mean(np.abs(pcm_samples - alaw_decoded))
    print(f"   A-law compression: {len(pcm_samples)*2} bytes -> {len(alaw_encoded)} bytes")
    print(f"   Average reconstruction error: {error:.2f}")

    # Test IMA ADPCM encoding/decoding
    print("\n4. Testing IMA ADPCM codec...")
    adpcm_encoded = IMAAdpcmCodec.encode(pcm_samples)
    adpcm_decoded = IMAAdpcmCodec.decode(adpcm_encoded)
    print(f"   ADPCM compression: {len(pcm_samples)*2} bytes -> {len(adpcm_encoded)} bytes")
    print(f"   Compression ratio: {len(pcm_samples)*2 / len(adpcm_encoded):.1f}:1")

    # Test Dialogic VOX encoding/decoding
    print("\n5. Testing Dialogic VOX codec...")
    vox_encoded = DialogicVox.encode(pcm_samples)
    vox_decoded = DialogicVox.decode(vox_encoded)
    print(f"   VOX compression: {len(pcm_samples)*2} bytes -> {len(vox_encoded)} bytes")

    # Test audio processing
    print("\n6. Testing audio processing...")
    normalized = AudioProcessor.normalize(audio, -6.0)
    print(f"   Normalized to -6dB: max amplitude = {np.max(np.abs(normalized.samples)):.4f}")

    resampled = AudioProcessor.resample(audio, 16000)
    print(f"   Resampled 8kHz -> 16kHz: {audio.num_samples} -> {resampled.num_samples} samples")

    amplified = AudioProcessor.amplify(audio, 6.0)
    print(f"   Amplified +6dB: max amplitude = {np.max(np.abs(amplified.samples)):.4f}")

    print("\n" + "=" * 60)
    print("Demo complete! All codecs and processors working.")
    print("=" * 60)

# Run demo if executed directly
if __name__ == "__main__":
    demo()
