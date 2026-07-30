module granite_policy
  use, intrinsic :: iso_c_binding, only: c_double, c_int
  implicit none
contains
  function arach_granite_readiness_score(features, count) result(score) bind(C)
    real(c_double), intent(in) :: features(*)
    integer(c_int), value, intent(in) :: count
    real(c_double) :: score
    integer :: index

    if (count < 4_c_int) then
      score = 0.0_c_double
      return
    end if
    score = 1.0_c_double
    do index = 1, 4
      score = score * max(0.0_c_double, min(1.0_c_double, features(index)))
    end do
  end function arach_granite_readiness_score
end module granite_policy
