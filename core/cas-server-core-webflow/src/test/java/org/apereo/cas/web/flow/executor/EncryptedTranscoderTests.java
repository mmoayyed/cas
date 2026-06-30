package org.apereo.cas.web.flow.executor;

import module java.base;
import org.apereo.cas.util.crypto.CipherExecutor;
import org.apereo.cas.web.flow.BaseWebflowConfigurerTests;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test cases for {@link EncryptedTranscoder}.
 *
 * @author Misagh Moayyed
 * @since 6.1
 */
@Tag("Webflow")
class EncryptedTranscoderTests extends BaseWebflowConfigurerTests {
    @ParameterizedTest
    @MethodSource("getAllowedEncodeDecodeParameters")
    void verifyEncodeDecode(final Serializable encodable, final boolean compression) throws Exception {
        val transcoder1 = new EncryptedTranscoder(webflowCipherExecutor, compression);
        val encoded = transcoder1.encode(encodable);
        assertEquals(encodable, transcoder1.decode(encoded));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void verifyRejectedDeserializationClass(final boolean compression) throws Throwable {
        val transcoder = new EncryptedTranscoder(CipherExecutor.noOp(), compression);
        val encoded = transcoder.encode(new URI("https://maps.google.com").toURL());
        assertThrows(IOException.class, () -> transcoder.decode(encoded));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void verifyRejectedDeserializationRootClass(final boolean compression) throws Throwable {
        val transcoder = new EncryptedTranscoder(CipherExecutor.noOp(), compression);
        val encoded = transcoder.encode(new HashMap<>());
        assertThrows(IOException.class, () -> transcoder.decode(encoded));
    }

    @ParameterizedTest
    @MethodSource("getAllowedRootClasses")
    void verifyFilterAllowsExpectedRootClasses(final Class<?> clazz) {
        assertEquals(ObjectInputFilter.Status.ALLOWED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(clazz, 1)));
    }

    @ParameterizedTest
    @MethodSource("getRejectedRootClasses")
    void verifyFilterRejectsUnexpectedRootClasses(final Class<?> clazz) {
        assertEquals(ObjectInputFilter.Status.REJECTED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(clazz, 1)));
    }

    @Test
    void verifyFilterAllowsExpectedDependencyClasses() {
        assertEquals(ObjectInputFilter.Status.ALLOWED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(HashMap.class, 2)));
        assertEquals(ObjectInputFilter.Status.ALLOWED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(String[].class, 2)));
        assertEquals(ObjectInputFilter.Status.ALLOWED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(byte[].class, 2)));
        assertEquals(ObjectInputFilter.Status.ALLOWED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(TestEnum.class, 2)));
    }

    @Test
    void verifyFilterRejectsUnexpectedDependencyClasses() {
        assertEquals(ObjectInputFilter.Status.REJECTED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(URL.class, 2)));
        assertEquals(ObjectInputFilter.Status.REJECTED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(URL[].class, 2)));
        assertEquals(ObjectInputFilter.Status.REJECTED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(Object.class, 2)));
    }

    @Test
    void verifyFilterRejectsExceededLimits() {
        assertEquals(ObjectInputFilter.Status.ALLOWED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(String.class, 64, 100_000, 100_000, 10_000_000)));
        assertEquals(ObjectInputFilter.Status.REJECTED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(String.class, 65, 1, 1, 1)));
        assertEquals(ObjectInputFilter.Status.REJECTED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(String.class, 1, 100_001, 1, 1)));
        assertEquals(ObjectInputFilter.Status.REJECTED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(String.class, 1, 1, 100_001, 1)));
        assertEquals(ObjectInputFilter.Status.REJECTED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(String.class, 1, 1, 1, 10_000_001)));
    }

    @Test
    void verifyFilterAllowsUndecidedClass() {
        assertEquals(ObjectInputFilter.Status.UNDECIDED,
            EncryptedTranscoder.validateDeserializedClass(filterInfo(null, 1)));
    }

    @Test
    void verifyBadEncoding() throws Throwable {
        val encoder = new EncryptedTranscoder(CipherExecutor.noOp());
        assertEquals(0, encoder.encode(null).length);
    }

    @Test
    void verifyNotSerializable() throws Throwable {
        val encoder = new EncryptedTranscoder(CipherExecutor.noOp());
        val encoded = encoder.encode(new Object());
        assertNotNull(encoded);
        assertThrows(IOException.class, () -> encoder.decode(encoded));
    }

    @Test
    void verifyBadDecoding() {
        val encoder = new EncryptedTranscoder(CipherExecutor.noOp());
        assertThrows(IOException.class, () -> encoder.decode(null));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void verifyMalformedDecodedBytes(final boolean compression) {
        val encoder = new EncryptedTranscoder(CipherExecutor.noOp(), compression);
        assertThrows(IOException.class, () -> encoder.decode("malformed".getBytes(StandardCharsets.UTF_8)));
    }

    private static Stream<Arguments> getAllowedEncodeDecodeParameters() {
        val values = List.<Serializable>of(
            "value",
            Boolean.TRUE,
            123,
            new BigInteger("123456789"),
            new BigDecimal("123.45"),
            URI.create("https://maps.google.com/maps?q=1600+Pennsylvania+Avenue"));
        return Stream.of(true, false)
            .flatMap(compression -> values.stream().map(value -> Arguments.of(value, compression)));
    }

    private static Stream<Class<?>> getAllowedRootClasses() {
        return Stream.of(
            String.class,
            Boolean.class,
            BigInteger.class,
            BigDecimal.class,
            URI.class,
            ClientFlowExecutionRepository.SerializedFlowExecutionState.class);
    }

    private static Stream<Class<?>> getRejectedRootClasses() {
        return Stream.of(
            HashMap.class,
            Object.class,
            URL.class,
            String[].class,
            byte[].class);
    }

    private static ObjectInputFilter.FilterInfo filterInfo(final Class<?> clazz, final long depth) {
        return filterInfo(clazz, depth, 1, -1, 1);
    }

    private static ObjectInputFilter.FilterInfo filterInfo(final Class<?> clazz, final long depth,
                                                          final long references, final long arrayLength,
                                                          final long streamBytes) {
        val info = mock(ObjectInputFilter.FilterInfo.class);
        doReturn(clazz).when(info).serialClass();
        when(info.depth()).thenReturn(depth);
        when(info.references()).thenReturn(references);
        when(info.arrayLength()).thenReturn(arrayLength);
        when(info.streamBytes()).thenReturn(streamBytes);
        return info;
    }

    private enum TestEnum {
        VALUE
    }
}
