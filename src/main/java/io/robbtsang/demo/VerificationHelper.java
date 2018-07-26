package io.robbtsang.demo;

public interface VerificationHelper<T> {
    default boolean verify(T ... parameters)  {
        return true;
    };
}
