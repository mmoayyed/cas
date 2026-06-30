package org.apereo.cas.web.flow.executor;

import module java.base;
import org.apereo.cas.util.LoggingUtils;
import org.apereo.cas.util.crypto.CipherExecutor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.support.AopUtils;

/**
 * Encodes an object by encrypting its serialized byte stream. Details of encryption are handled by an instance of
 * {@link CipherExecutor}.
 * <p>
 * Optional gzip compression of the serialized byte stream before encryption is supported and enabled by default.
 *
 * @author Marvin S. Addison
 * @author Misagh Moayyed
 * @since 6.1
 */
@Slf4j
@RequiredArgsConstructor
public class EncryptedTranscoder implements Transcoder {
    private static final long MAXIMUM_DESERIALIZATION_DEPTH = 64;

    private static final long MAXIMUM_DESERIALIZATION_REFERENCES = 100_000;

    private static final long MAXIMUM_DESERIALIZATION_ARRAY_LENGTH = 100_000;

    private static final long MAXIMUM_DESERIALIZATION_BYTES = 10_000_000;

    private static final Set<String> ALLOWED_DESERIALIZATION_ROOT_CLASS_NAMES = Set.of(
        Boolean.class.getName(),
        Byte.class.getName(),
        Character.class.getName(),
        Double.class.getName(),
        Float.class.getName(),
        Integer.class.getName(),
        Long.class.getName(),
        Number.class.getName(),
        Short.class.getName(),
        String.class.getName(),
        BigDecimal.class.getName(),
        BigInteger.class.getName(),
        URI.class.getName(),
        ClientFlowExecutionRepository.SerializedFlowExecutionState.class.getName());

    private static final Set<String> ALLOWED_DESERIALIZATION_CLASS_NAMES = Set.of(
        Boolean.class.getName(),
        Byte.class.getName(),
        Character.class.getName(),
        Double.class.getName(),
        Float.class.getName(),
        Integer.class.getName(),
        Long.class.getName(),
        Number.class.getName(),
        Short.class.getName(),
        String.class.getName(),
        BigDecimal.class.getName(),
        BigInteger.class.getName(),
        URI.class.getName(),
        ClientFlowExecutionRepository.SerializedFlowExecutionState.class.getName());

    private static final Set<String> ALLOWED_DESERIALIZATION_PACKAGE_NAMES = Set.of(
        "java.time.",
        "java.util.",
        "org.apereo.",
        "org.springframework.");

    /**
     * Handles encryption/decryption details.
     */
    private final CipherExecutor cipherExecutor;

    /**
     * Flag to indicate whether to Gzip compression before encryption.
     */
    private final boolean compression;

    public EncryptedTranscoder(final CipherExecutor cipherBean) {
        this(cipherBean, true);
    }

    @Override
    public byte[] encode(final Object o) throws IOException {
        if (o == null) {
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }
        try (val outBuffer = new ByteArrayOutputStream()) {
            try (val out = this.compression
                ? new ObjectOutputStream(new GZIPOutputStream(outBuffer))
                : new ObjectOutputStream(outBuffer)) {

                writeObjectToOutputStream(o, out);
            } catch (final NotSerializableException e) {
                LoggingUtils.warn(LOGGER, e);
            }
            return encrypt(outBuffer);
        }
    }


    @Override
    @SuppressWarnings("BanSerializableRead")
    public Object decode(final byte[] encoded) throws IOException {
        val data = decrypt(encoded);
        try (val inBuffer = new ByteArrayInputStream(data);
             val in = this.compression
                 ? new ObjectInputStream(new GZIPInputStream(inBuffer))
                 : new ObjectInputStream(inBuffer)) {
            in.setObjectInputFilter(EncryptedTranscoder::validateDeserializedClass);
            return in.readObject();
        } catch (final Exception e) {
            LoggingUtils.error(LOGGER, e);
            throw new IOException("Deserialization error", e);
        }
    }

    protected static ObjectInputFilter.Status validateDeserializedClass(final ObjectInputFilter.FilterInfo info) {
        if (isDeserializationLimitExceeded(info)) {
            return ObjectInputFilter.Status.REJECTED;
        }
        val serialClass = info.serialClass();
        if (serialClass == null) {
            return ObjectInputFilter.Status.UNDECIDED;
        }
        if (info.depth() == 1 && !isDeserializationRootClassAllowed(serialClass)) {
            return ObjectInputFilter.Status.REJECTED;
        }
        if (serialClass.isArray()) {
            return validateDeserializedArrayClass(serialClass);
        }
        return isDeserializationClassAllowed(serialClass)
            ? ObjectInputFilter.Status.ALLOWED
            : ObjectInputFilter.Status.REJECTED;
    }

    private static ObjectInputFilter.Status validateDeserializedArrayClass(final Class<?> serialClass) {
        var componentType = serialClass.getComponentType();
        while (componentType.isArray()) {
            componentType = componentType.getComponentType();
        }
        return componentType.isPrimitive() || isDeserializationClassAllowed(componentType)
            ? ObjectInputFilter.Status.ALLOWED
            : ObjectInputFilter.Status.REJECTED;
    }

    private static boolean isDeserializationLimitExceeded(final ObjectInputFilter.FilterInfo info) {
        return info.depth() > MAXIMUM_DESERIALIZATION_DEPTH
            || info.references() > MAXIMUM_DESERIALIZATION_REFERENCES
            || info.arrayLength() > MAXIMUM_DESERIALIZATION_ARRAY_LENGTH
            || info.streamBytes() > MAXIMUM_DESERIALIZATION_BYTES;
    }

    private static boolean isDeserializationClassAllowed(final Class<?> serialClass) {
        if (serialClass.isPrimitive() || Enum.class.isAssignableFrom(serialClass)) {
            return true;
        }
        val className = serialClass.getName();
        return ALLOWED_DESERIALIZATION_CLASS_NAMES.contains(className)
            || ALLOWED_DESERIALIZATION_PACKAGE_NAMES.stream().anyMatch(className::startsWith);
    }

    private static boolean isDeserializationRootClassAllowed(final Class<?> serialClass) {
        return !serialClass.isArray()
            && (serialClass.isPrimitive()
                || Enum.class.isAssignableFrom(serialClass)
                || ALLOWED_DESERIALIZATION_ROOT_CLASS_NAMES.contains(serialClass.getName()));
    }

    @SuppressWarnings("BanSerializableRead")
    protected void writeObjectToOutputStream(final Object o, final ObjectOutputStream out) throws IOException {
        var object = o;
        if (AopUtils.isAopProxy(o)) {
            try {
                object = ((Advised) o).getTargetSource().getTarget();
            } catch (final Exception e) {
                LoggingUtils.error(LOGGER, e);
            }
            if (object == null) {
                LOGGER.error("Could not determine object [{}] from proxy",
                    Objects.requireNonNull(o).getClass().getSimpleName());
            }
        }
        if (object != null) {
            out.writeObject(object);
        } else {
            LOGGER.warn("Unable to write object [{}] to the output stream", o);
        }
    }

    protected byte[] encrypt(final ByteArrayOutputStream outBuffer) {
        return (byte[]) cipherExecutor.encode(outBuffer.toByteArray());
    }

    private byte[] decrypt(final byte[] encoded) {
        return (byte[]) cipherExecutor.decode(encoded);
    }
}
