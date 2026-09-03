package ch.rasc.webauthn.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class Base58Test {

  @ParameterizedTest
  @MethodSource("vectors")
  void encodesAndDecodesKnownVectors(byte[] input, String encoded) {
    assertEquals(encoded, Base58.encode(input));
    assertArrayEquals(input, Base58.decode(encoded));
  }

  @Test
  void rejectsCharactersOutsideTheAlphabet() {
    assertThrows(IllegalArgumentException.class, () -> Base58.decode("0OIl"));
    assertThrows(IllegalArgumentException.class, () -> Base58.decode("abcé"));
  }

  private static Stream<Arguments> vectors() {
    return Stream.of(Arguments.of(new byte[0], ""),
        Arguments.of(new byte[] { 0 }, "1"),
        Arguments.of(new byte[] { 0, 0, 1 }, "112"),
        Arguments.of("Hello World".getBytes(StandardCharsets.UTF_8),
            "JxF12TrwUP45BMd"));
  }

}
