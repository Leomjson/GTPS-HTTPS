#ifndef NLOHMANN_JSON_HPP
#define NLOHMANN_JSON_HPP

#define NLOHMANN_JSON_VERSION_MAJOR 3
#define NLOHMANN_JSON_VERSION_MINOR 2
#define NLOHMANN_JSON_VERSION_PATCH 0

#include <algorithm>
#include <cassert>
#include <ciso646>
#include <cstddef>
#include <functional>
#include <initializer_list>
#include <iosfwd>
#include <iterator>
#include <numeric>
#include <string>
#include <utility>
#ifndef NLOHMANN_JSON_FWD_HPP
#define NLOHMANN_JSON_FWD_HPP
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>
namespace nlohmann
{
template<typename T = void, typename SFINAE = void>
struct adl_serializer;
template<template<typename U, typename V, typename... Args> class ObjectType =
         std::map,
         template<typename U, typename... Args> class ArrayType = std::vector,
         class StringType = std::string, class BooleanType = bool,
         class NumberIntegerType = std::int64_t,
         class NumberUnsignedType = std::uint64_t,
         class NumberFloatType = double,
         template<typename U> class AllocatorType = std::allocator,
         template<typename T, typename SFINAE = void> class JSONSerializer =
         adl_serializer>
class basic_json;
template<typename BasicJsonType>
class json_pointer;
using json = basic_json<>;
}
#endif
#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
    #define JSON_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
    #define JSON_DEPRECATED __declspec(deprecated)
#else
    #define JSON_DEPRECATED
#endif
#if (defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)) && !defined(JSON_NOEXCEPTION)
    #define JSON_THROW(exception) throw exception
    #define JSON_TRY try
    #define JSON_CATCH(exception) catch(exception)
    #define JSON_INTERNAL_CATCH(exception) catch(exception)
#endif
#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
    #define JSON_LIKELY(x)      __builtin_expect(!!(x), 1)
    #define JSON_UNLIKELY(x)    __builtin_expect(!!(x), 0)
#else
    #define JSON_LIKELY(x)      x
    #define JSON_UNLIKELY(x)    x
#endif

#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_HAS_CXX17) && _HAS_CXX17 == 1)     
    #define JSON_HAS_CPP_17
    #define JSON_HAS_CPP_14
#elif (defined(__cplusplus) && __cplusplus >= 201402L) || (defined(_HAS_CXX14) && _HAS_CXX14 == 1)
    #define JSON_HAS_CPP_14
#endif
#define NLOHMANN_BASIC_JSON_TPL_DECLARATION                                \
    template<template<typename, typename, typename...> class ObjectType,   \
             template<typename, typename...> class ArrayType,              \
             class StringType, class BooleanType, class NumberIntegerType, \
             class NumberUnsignedType, class NumberFloatType,              \
             template<typename> class AllocatorType,                       \
             template<typename, typename = void> class JSONSerializer>

#define NLOHMANN_BASIC_JSON_TPL                                            \
    basic_json<ObjectType, ArrayType, StringType, BooleanType,             \
    NumberIntegerType, NumberUnsignedType, NumberFloatType,                \
    AllocatorType, JSONSerializer>

#define NLOHMANN_JSON_HAS_HELPER(type)                                        \
    template<typename T> struct has_##type {                                  \
    private:                                                                  \
        template<typename U, typename = typename U::type>                     \
        static int detect(U &&);                                              \
        static void detect(...);                                              \
    public:                                                                   \
        static constexpr bool value =                                         \
                std::is_integral<decltype(detect(std::declval<T>()))>::value; \
    }
#include <ciso646>
#include <cstddef>
#include <type_traits>
namespace nlohmann
{
namespace detail
{
template<bool B, typename T = void>
using enable_if_t = typename std::enable_if<B, T>::type;
template<typename T>
using uncvref_t = typename std::remove_cv<typename std::remove_reference<T>::type>::type;
template<std::size_t... Ints>
struct index_sequence
{
    using type = index_sequence;
    using value_type = std::size_t;
    static constexpr std::size_t size() noexcept
    {
        return sizeof...(Ints);
    }
};
template<class Sequence1, class Sequence2>
struct merge_and_renumber;
template<std::size_t... I1, std::size_t... I2>
struct merge_and_renumber<index_sequence<I1...>, index_sequence<I2...>>
        : index_sequence < I1..., (sizeof...(I1) + I2)... > {};

template<std::size_t N>
struct make_index_sequence
    : merge_and_renumber < typename make_index_sequence < N / 2 >::type,
      typename make_index_sequence < N - N / 2 >::type > {};

template<> struct make_index_sequence<0> : index_sequence<> {};
template<> struct make_index_sequence<1> : index_sequence<0> {};

template<typename... Ts>
using index_sequence_for = make_index_sequence<sizeof...(Ts)>;

template<class...> struct conjunction : std::true_type {};
template<class B1> struct conjunction<B1> : B1 {};
template<class B1, class... Bn>
struct conjunction<B1, Bn...> : std::conditional<bool(B1::value), conjunction<Bn...>, B1>::type {};

template<class B> struct negation : std::integral_constant<bool, not B::value> {};

template<unsigned N> struct priority_tag : priority_tag < N - 1 > {};
template<> struct priority_tag<0> {};

template<typename T>
struct static_const
{
    static constexpr T value{};
};

template<typename T>
constexpr T static_const<T>::value;
}
}
#include <ciso646>
#include <limits>
#include <type_traits>
#include <utility>
namespace nlohmann
{
namespace detail
{
template<typename> struct is_basic_json : std::false_type {};

NLOHMANN_BASIC_JSON_TPL_DECLARATION
struct is_basic_json<NLOHMANN_BASIC_JSON_TPL> : std::true_type {};

template <typename T, typename = void>
struct is_complete_type : std::false_type {};

template <typename T>
struct is_complete_type<T, decltype(void(sizeof(T)))> : std::true_type {};

NLOHMANN_JSON_HAS_HELPER(mapped_type);
NLOHMANN_JSON_HAS_HELPER(key_type);
NLOHMANN_JSON_HAS_HELPER(value_type);
NLOHMANN_JSON_HAS_HELPER(iterator);

template<bool B, class RealType, class CompatibleObjectType>
struct is_compatible_object_type_impl : std::false_type {};

template<class RealType, class CompatibleObjectType>
struct is_compatible_object_type_impl<true, RealType, CompatibleObjectType>
{
    static constexpr auto value =
        std::is_constructible<typename RealType::key_type, typename CompatibleObjectType::key_type>::value and
        std::is_constructible<typename RealType::mapped_type, typename CompatibleObjectType::mapped_type>::value;
};

template<bool B, class RealType, class CompatibleStringType>
struct is_compatible_string_type_impl : std::false_type {};

template<class RealType, class CompatibleStringType>
struct is_compatible_string_type_impl<true, RealType, CompatibleStringType>
{
    static constexpr auto value =
        std::is_same<typename RealType::value_type, typename CompatibleStringType::value_type>::value and
        std::is_constructible<RealType, CompatibleStringType>::value;
};

template<class BasicJsonType, class CompatibleObjectType>
struct is_compatible_object_type
{
    static auto constexpr value = is_compatible_object_type_impl <
                                  conjunction<negation<std::is_same<void, CompatibleObjectType>>,
                                  has_mapped_type<CompatibleObjectType>,
                                  has_key_type<CompatibleObjectType>>::value,
                                  typename BasicJsonType::object_t, CompatibleObjectType >::value;
};

template<class BasicJsonType, class CompatibleStringType>
struct is_compatible_string_type
{
    static auto constexpr value = is_compatible_string_type_impl <
                                  conjunction<negation<std::is_same<void, CompatibleStringType>>,
                                  has_value_type<CompatibleStringType>>::value,
                                  typename BasicJsonType::string_t, CompatibleStringType >::value;
};

template<typename BasicJsonType, typename T>
struct is_basic_json_nested_type
{
    static auto constexpr value = std::is_same<T, typename BasicJsonType::iterator>::value or
                                  std::is_same<T, typename BasicJsonType::const_iterator>::value or
                                  std::is_same<T, typename BasicJsonType::reverse_iterator>::value or
                                  std::is_same<T, typename BasicJsonType::const_reverse_iterator>::value;
};

template<class BasicJsonType, class CompatibleArrayType>
struct is_compatible_array_type
{
    static auto constexpr value =
        conjunction<negation<std::is_same<void, CompatibleArrayType>>,
        negation<is_compatible_object_type<
        BasicJsonType, CompatibleArrayType>>,
        negation<std::is_constructible<typename BasicJsonType::string_t,
        CompatibleArrayType>>,
        negation<is_basic_json_nested_type<BasicJsonType, CompatibleArrayType>>,
        has_value_type<CompatibleArrayType>,
        has_iterator<CompatibleArrayType>>::value;
};

template<bool, typename, typename>
struct is_compatible_integer_type_impl : std::false_type {};

template<typename RealIntegerType, typename CompatibleNumberIntegerType>
struct is_compatible_integer_type_impl<true, RealIntegerType, CompatibleNumberIntegerType>
{
    using RealLimits = std::numeric_limits<RealIntegerType>;
    using CompatibleLimits = std::numeric_limits<CompatibleNumberIntegerType>;

    static constexpr auto value =
        std::is_constructible<RealIntegerType, CompatibleNumberIntegerType>::value and
        CompatibleLimits::is_integer and
        RealLimits::is_signed == CompatibleLimits::is_signed;
};

template<typename RealIntegerType, typename CompatibleNumberIntegerType>
struct is_compatible_integer_type
{
    static constexpr auto value =
        is_compatible_integer_type_impl <
        std::is_integral<CompatibleNumberIntegerType>::value and
        not std::is_same<bool, CompatibleNumberIntegerType>::value,
        RealIntegerType, CompatibleNumberIntegerType > ::value;
};

template<typename BasicJsonType, typename T>
struct has_from_json
{
  private:
    template<typename U, typename = enable_if_t<std::is_same<void, decltype(uncvref_t<U>::from_json(
                 std::declval<BasicJsonType>(), std::declval<T&>()))>::value>>
    static int detect(U&&);
    static void detect(...);

  public:
    static constexpr bool value = std::is_integral<decltype(
                                      detect(std::declval<typename BasicJsonType::template json_serializer<T, void>>()))>::value;
};

template<typename BasicJsonType, typename T>
struct has_non_default_from_json
{
  private:
    template <
        typename U,
        typename = enable_if_t<std::is_same<
                                   T, decltype(uncvref_t<U>::from_json(std::declval<BasicJsonType>()))>::value >>
    static int detect(U&&);
    static void detect(...);

  public:
    static constexpr bool value = std::is_integral<decltype(detect(
                                      std::declval<typename BasicJsonType::template json_serializer<T, void>>()))>::value;
};

template<typename BasicJsonType, typename T>
struct has_to_json
{
  private:
    template<typename U, typename = decltype(uncvref_t<U>::to_json(
                 std::declval<BasicJsonType&>(), std::declval<T>()))>
    static int detect(U&&);
    static void detect(...);

  public:
    static constexpr bool value = std::is_integral<decltype(detect(
                                      std::declval<typename BasicJsonType::template json_serializer<T, void>>()))>::value;
};

template <typename BasicJsonType, typename CompatibleCompleteType>
struct is_compatible_complete_type
{
    static constexpr bool value =
        not std::is_base_of<std::istream, CompatibleCompleteType>::value and
        not is_basic_json<CompatibleCompleteType>::value and
        not is_basic_json_nested_type<BasicJsonType, CompatibleCompleteType>::value and
        has_to_json<BasicJsonType, CompatibleCompleteType>::value;
};

template <typename BasicJsonType, typename CompatibleType>
struct is_compatible_type
    : conjunction<is_complete_type<CompatibleType>,
      is_compatible_complete_type<BasicJsonType, CompatibleType>>
{
};
}
}


#include <exception>  
#include <stdexcept>  
#include <string>  

namespace nlohmann
{
namespace detail
{
class exception : public std::exception
{
  public:
    const char* what() const noexcept override
    {
        return m.what();
    }

    const int id;

  protected:
    exception(int id_, const char* what_arg) : id(id_), m(what_arg) {}

    static std::string name(const std::string& ename, int id_)
    {
        return "[json.exception." + ename + "." + std::to_string(id_) + "] ";
    }

  private:
    std::runtime_error m;
};

class parse_error : public exception
{
  public:
    static parse_error create(int id_, std::size_t byte_, const std::string& what_arg)
    {
        std::string w = exception::name("parse_error", id_) + "parse error" +
                        (byte_ != 0 ? (" at " + std::to_string(byte_)) : "") +
                        ": " + what_arg;
        return parse_error(id_, byte_, w.c_str());
    }

    const std::size_t byte;

  private:
    parse_error(int id_, std::size_t byte_, const char* what_arg)
        : exception(id_, what_arg), byte(byte_) {}
};

class invalid_iterator : public exception
{
  public:
    static invalid_iterator create(int id_, const std::string& what_arg)
    {
        std::string w = exception::name("invalid_iterator", id_) + what_arg;
        return invalid_iterator(id_, w.c_str());
    }

  private:
    invalid_iterator(int id_, const char* what_arg)
        : exception(id_, what_arg) {}
};

class type_error : public exception
{
  public:
    static type_error create(int id_, const std::string& what_arg)
    {
        std::string w = exception::name("type_error", id_) + what_arg;
        return type_error(id_, w.c_str());
    }

  private:
    type_error(int id_, const char* what_arg) : exception(id_, what_arg) {}
};

class out_of_range : public exception
{
  public:
    static out_of_range create(int id_, const std::string& what_arg)
    {
        std::string w = exception::name("out_of_range", id_) + what_arg;
        return out_of_range(id_, w.c_str());
    }

  private:
    out_of_range(int id_, const char* what_arg) : exception(id_, what_arg) {}
};

class other_error : public exception
{
  public:
    static other_error create(int id_, const std::string& what_arg)
    {
        std::string w = exception::name("other_error", id_) + what_arg;
        return other_error(id_, w.c_str());
    }

  private:
    other_error(int id_, const char* what_arg) : exception(id_, what_arg) {}
};
}
}


#include <array>  
#include <ciso646>  
#include <cstddef>  
#include <cstdint>  

namespace nlohmann
{
namespace detail
{
enum class value_t : std::uint8_t
{
    null,               
    object,                 
    array,                 
    string,             
    boolean,            
    number_integer,       
    number_unsigned,      
    number_float,        
    discarded                
};

inline bool operator<(const value_t lhs, const value_t rhs) noexcept
{
    static constexpr std::array<std::uint8_t, 8> order = {{
            0   , 3   , 4   , 5   ,
            1   , 2   , 2   , 2   
        }
    };

    const auto l_index = static_cast<std::size_t>(lhs);
    const auto r_index = static_cast<std::size_t>(rhs);
    return l_index < order.size() and r_index < order.size() and order[l_index] < order[r_index];
}
}
}


#include <algorithm>  
#include <array>  
#include <ciso646>   
#include <forward_list>  
#include <iterator>    
#include <map>  
#include <string>  
#include <tuple>   
#include <type_traits>      
#include <unordered_map>  
#include <utility>   
#include <valarray>  


namespace nlohmann
{
namespace detail
{
template<typename BasicJsonType>
void from_json(const BasicJsonType& j, typename std::nullptr_t& n)
{
    if (JSON_UNLIKELY(not j.is_null()))
    {
        JSON_THROW(type_error::create(302, "type must be null, but is " + std::string(j.type_name())));
    }
    n = nullptr;
}

template<typename BasicJsonType, typename ArithmeticType,
         enable_if_t<std::is_arithmetic<ArithmeticType>::value and
                     not std::is_same<ArithmeticType, typename BasicJsonType::boolean_t>::value,
                     int> = 0>
void get_arithmetic_value(const BasicJsonType& j, ArithmeticType& val)
{
    switch (static_cast<value_t>(j))
    {
        case value_t::number_unsigned:
        {
            val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::number_unsigned_t*>());
            break;
        }
        case value_t::number_integer:
        {
            val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::number_integer_t*>());
            break;
        }
        case value_t::number_float:
        {
            val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::number_float_t*>());
            break;
        }

        default:
            JSON_THROW(type_error::create(302, "type must be number, but is " + std::string(j.type_name())));
    }
}

template<typename BasicJsonType>
void from_json(const BasicJsonType& j, typename BasicJsonType::boolean_t& b)
{
    if (JSON_UNLIKELY(not j.is_boolean()))
    {
        JSON_THROW(type_error::create(302, "type must be boolean, but is " + std::string(j.type_name())));
    }
    b = *j.template get_ptr<const typename BasicJsonType::boolean_t*>();
}

template<typename BasicJsonType>
void from_json(const BasicJsonType& j, typename BasicJsonType::string_t& s)
{
    if (JSON_UNLIKELY(not j.is_string()))
    {
        JSON_THROW(type_error::create(302, "type must be string, but is " + std::string(j.type_name())));
    }
    s = *j.template get_ptr<const typename BasicJsonType::string_t*>();
}

template <
    typename BasicJsonType, typename CompatibleStringType,
    enable_if_t <
        is_compatible_string_type<BasicJsonType, CompatibleStringType>::value and
        not std::is_same<typename BasicJsonType::string_t,
                         CompatibleStringType>::value,
        int > = 0 >
void from_json(const BasicJsonType& j, CompatibleStringType& s)
{
    if (JSON_UNLIKELY(not j.is_string()))
    {
        JSON_THROW(type_error::create(302, "type must be string, but is " + std::string(j.type_name())));
    }

    s = *j.template get_ptr<const typename BasicJsonType::string_t*>();
}

template<typename BasicJsonType>
void from_json(const BasicJsonType& j, typename BasicJsonType::number_float_t& val)
{
    get_arithmetic_value(j, val);
}

template<typename BasicJsonType>
void from_json(const BasicJsonType& j, typename BasicJsonType::number_unsigned_t& val)
{
    get_arithmetic_value(j, val);
}

template<typename BasicJsonType>
void from_json(const BasicJsonType& j, typename BasicJsonType::number_integer_t& val)
{
    get_arithmetic_value(j, val);
}

template<typename BasicJsonType, typename EnumType,
         enable_if_t<std::is_enum<EnumType>::value, int> = 0>
void from_json(const BasicJsonType& j, EnumType& e)
{
    typename std::underlying_type<EnumType>::type val;
    get_arithmetic_value(j, val);
    e = static_cast<EnumType>(val);
}

template<typename BasicJsonType>
void from_json(const BasicJsonType& j, typename BasicJsonType::array_t& arr)
{
    if (JSON_UNLIKELY(not j.is_array()))
    {
        JSON_THROW(type_error::create(302, "type must be array, but is " + std::string(j.type_name())));
    }
    arr = *j.template get_ptr<const typename BasicJsonType::array_t*>();
}

template<typename BasicJsonType, typename T, typename Allocator,
         enable_if_t<std::is_convertible<BasicJsonType, T>::value, int> = 0>
void from_json(const BasicJsonType& j, std::forward_list<T, Allocator>& l)
{
    if (JSON_UNLIKELY(not j.is_array()))
    {
        JSON_THROW(type_error::create(302, "type must be array, but is " + std::string(j.type_name())));
    }
    std::transform(j.rbegin(), j.rend(),
                   std::front_inserter(l), [](const BasicJsonType & i)
    {
        return i.template get<T>();
    });
}

template<typename BasicJsonType, typename T,
         enable_if_t<std::is_convertible<BasicJsonType, T>::value, int> = 0>
void from_json(const BasicJsonType& j, std::valarray<T>& l)
{
    if (JSON_UNLIKELY(not j.is_array()))
    {
        JSON_THROW(type_error::create(302, "type must be array, but is " + std::string(j.type_name())));
    }
    l.resize(j.size());
    std::copy(j.m_value.array->begin(), j.m_value.array->end(), std::begin(l));
}

template<typename BasicJsonType, typename CompatibleArrayType>
void from_json_array_impl(const BasicJsonType& j, CompatibleArrayType& arr, priority_tag<0> )
{
    using std::end;

    std::transform(j.begin(), j.end(),
                   std::inserter(arr, end(arr)), [](const BasicJsonType & i)
    {
        return i.template get<typename CompatibleArrayType::value_type>();
    });
}

template<typename BasicJsonType, typename CompatibleArrayType>
auto from_json_array_impl(const BasicJsonType& j, CompatibleArrayType& arr, priority_tag<1> )
-> decltype(
    arr.reserve(std::declval<typename CompatibleArrayType::size_type>()),
    void())
{
    using std::end;

    arr.reserve(j.size());
    std::transform(j.begin(), j.end(),
                   std::inserter(arr, end(arr)), [](const BasicJsonType & i)
    {
        return i.template get<typename CompatibleArrayType::value_type>();
    });
}

template<typename BasicJsonType, typename T, std::size_t N>
void from_json_array_impl(const BasicJsonType& j, std::array<T, N>& arr, priority_tag<2> )
{
    for (std::size_t i = 0; i < N; ++i)
    {
        arr[i] = j.at(i).template get<T>();
    }
}

template <
    typename BasicJsonType, typename CompatibleArrayType,
    enable_if_t <
        is_compatible_array_type<BasicJsonType, CompatibleArrayType>::value and
        not std::is_same<typename BasicJsonType::array_t,
                         CompatibleArrayType>::value and
        std::is_constructible <
            BasicJsonType, typename CompatibleArrayType::value_type >::value,
        int > = 0 >
void from_json(const BasicJsonType& j, CompatibleArrayType& arr)
{
    if (JSON_UNLIKELY(not j.is_array()))
    {
        JSON_THROW(type_error::create(302, "type must be array, but is " +
                                      std::string(j.type_name())));
    }

    from_json_array_impl(j, arr, priority_tag<2> {});
}

template<typename BasicJsonType, typename CompatibleObjectType,
         enable_if_t<is_compatible_object_type<BasicJsonType, CompatibleObjectType>::value, int> = 0>
void from_json(const BasicJsonType& j, CompatibleObjectType& obj)
{
    if (JSON_UNLIKELY(not j.is_object()))
    {
        JSON_THROW(type_error::create(302, "type must be object, but is " + std::string(j.type_name())));
    }

    auto inner_object = j.template get_ptr<const typename BasicJsonType::object_t*>();
    using value_type = typename CompatibleObjectType::value_type;
    std::transform(
        inner_object->begin(), inner_object->end(),
        std::inserter(obj, obj.begin()),
        [](typename BasicJsonType::object_t::value_type const & p)
    {
        return value_type(p.first, p.second.template get<typename CompatibleObjectType::mapped_type>());
    });
}

template<typename BasicJsonType, typename ArithmeticType,
         enable_if_t <
             std::is_arithmetic<ArithmeticType>::value and
             not std::is_same<ArithmeticType, typename BasicJsonType::number_unsigned_t>::value and
             not std::is_same<ArithmeticType, typename BasicJsonType::number_integer_t>::value and
             not std::is_same<ArithmeticType, typename BasicJsonType::number_float_t>::value and
             not std::is_same<ArithmeticType, typename BasicJsonType::boolean_t>::value,
             int> = 0>
void from_json(const BasicJsonType& j, ArithmeticType& val)
{
    switch (static_cast<value_t>(j))
    {
        case value_t::number_unsigned:
        {
            val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::number_unsigned_t*>());
            break;
        }
        case value_t::number_integer:
        {
            val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::number_integer_t*>());
            break;
        }
        case value_t::number_float:
        {
            val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::number_float_t*>());
            break;
        }
        case value_t::boolean:
        {
            val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::boolean_t*>());
            break;
        }

        default:
            JSON_THROW(type_error::create(302, "type must be number, but is " + std::string(j.type_name())));
    }
}

template<typename BasicJsonType, typename A1, typename A2>
void from_json(const BasicJsonType& j, std::pair<A1, A2>& p)
{
    p = {j.at(0).template get<A1>(), j.at(1).template get<A2>()};
}

template<typename BasicJsonType, typename Tuple, std::size_t... Idx>
void from_json_tuple_impl(const BasicJsonType& j, Tuple& t, index_sequence<Idx...>)
{
    t = std::make_tuple(j.at(Idx).template get<typename std::tuple_element<Idx, Tuple>::type>()...);
}

template<typename BasicJsonType, typename... Args>
void from_json(const BasicJsonType& j, std::tuple<Args...>& t)
{
    from_json_tuple_impl(j, t, index_sequence_for<Args...> {});
}

template <typename BasicJsonType, typename Key, typename Value, typename Compare, typename Allocator,
          typename = enable_if_t<not std::is_constructible<
                                     typename BasicJsonType::string_t, Key>::value>>
void from_json(const BasicJsonType& j, std::map<Key, Value, Compare, Allocator>& m)
{
    if (JSON_UNLIKELY(not j.is_array()))
    {
        JSON_THROW(type_error::create(302, "type must be array, but is " + std::string(j.type_name())));
    }
    for (const auto& p : j)
    {
        if (JSON_UNLIKELY(not p.is_array()))
        {
            JSON_THROW(type_error::create(302, "type must be array, but is " + std::string(p.type_name())));
        }
        m.emplace(p.at(0).template get<Key>(), p.at(1).template get<Value>());
    }
}

template <typename BasicJsonType, typename Key, typename Value, typename Hash, typename KeyEqual, typename Allocator,
          typename = enable_if_t<not std::is_constructible<
                                     typename BasicJsonType::string_t, Key>::value>>
void from_json(const BasicJsonType& j, std::unordered_map<Key, Value, Hash, KeyEqual, Allocator>& m)
{
    if (JSON_UNLIKELY(not j.is_array()))
    {
        JSON_THROW(type_error::create(302, "type must be array, but is " + std::string(j.type_name())));
    }
    for (const auto& p : j)
    {
        if (JSON_UNLIKELY(not p.is_array()))
        {
            JSON_THROW(type_error::create(302, "type must be array, but is " + std::string(p.type_name())));
        }
        m.emplace(p.at(0).template get<Key>(), p.at(1).template get<Value>());
    }
}

struct from_json_fn
{
  private:
    template<typename BasicJsonType, typename T>
    auto call(const BasicJsonType& j, T& val, priority_tag<1> ) const
    noexcept(noexcept(from_json(j, val)))
    -> decltype(from_json(j, val), void())
    {
        return from_json(j, val);
    }

    template<typename BasicJsonType, typename T>
    void call(const BasicJsonType& , T& , priority_tag<0> ) const noexcept
    {
        static_assert(sizeof(BasicJsonType) == 0,
                      "could not find from_json() method in T's namespace");
#ifdef _MSC_VER
        using decayed = uncvref_t<T>;
        static_assert(sizeof(typename decayed::force_msvc_stacktrace) == 0,
                      "forcing MSVC stacktrace to show which T we're talking about.");
#endif
    }

  public:
    template<typename BasicJsonType, typename T>
    void operator()(const BasicJsonType& j, T& val) const
    noexcept(noexcept(std::declval<from_json_fn>().call(j, val, priority_tag<1> {})))
    {
        return call(j, val, priority_tag<1> {});
    }
};
}

namespace
{
constexpr const auto& from_json = detail::static_const<detail::from_json_fn>::value;
}
}


#include <ciso646>    
#include <iterator>   
#include <tuple>   
#include <type_traits>      
#include <utility>     
#include <valarray>  
#include <vector>  


#include <cstddef>  
#include <string>   
#include <iterator>  


namespace nlohmann
{
namespace detail
{
template<typename IteratorType> class iteration_proxy
{
  private:
    class iteration_proxy_internal
    {
      public:
        using difference_type = std::ptrdiff_t;
        using value_type = iteration_proxy_internal;
        using pointer = iteration_proxy_internal*;
        using reference = iteration_proxy_internal&;
        using iterator_category = std::input_iterator_tag;

      private:
        IteratorType anchor;
        std::size_t array_index = 0;
        mutable std::size_t array_index_last = 0;
        mutable std::string array_index_str = "0";
        const std::string empty_str = "";

      public:
        explicit iteration_proxy_internal(IteratorType it) noexcept : anchor(it) {}

        iteration_proxy_internal(const iteration_proxy_internal&) = default;
        iteration_proxy_internal& operator=(const iteration_proxy_internal&) = default;

        iteration_proxy_internal& operator*()
        {
            return *this;
        }

        iteration_proxy_internal& operator++()
        {
            ++anchor;
            ++array_index;

            return *this;
        }

        bool operator==(const iteration_proxy_internal& o) const noexcept
        {
            return anchor == o.anchor;
        }

        bool operator!=(const iteration_proxy_internal& o) const noexcept
        {
            return anchor != o.anchor;
        }

        const std::string& key() const
        {
            assert(anchor.m_object != nullptr);

            switch (anchor.m_object->type())
            {
                case value_t::array:
                {
                    if (array_index != array_index_last)
                    {
                        array_index_str = std::to_string(array_index);
                        array_index_last = array_index;
                    }
                    return array_index_str;
                }

                case value_t::object:
                    return anchor.key();

                default:
                    return empty_str;
            }
        }

        typename IteratorType::reference value() const
        {
            return anchor.value();
        }
    };

    typename IteratorType::reference container;

  public:
    explicit iteration_proxy(typename IteratorType::reference cont) noexcept
        : container(cont) {}

    iteration_proxy_internal begin() noexcept
    {
        return iteration_proxy_internal(container.begin());
    }

    iteration_proxy_internal end() noexcept
    {
        return iteration_proxy_internal(container.end());
    }
};
}
}


namespace nlohmann
{
namespace detail
{
template<value_t> struct external_constructor;

template<>
struct external_constructor<value_t::boolean>
{
    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, typename BasicJsonType::boolean_t b) noexcept
    {
        j.m_type = value_t::boolean;
        j.m_value = b;
        j.assert_invariant();
    }
};

template<>
struct external_constructor<value_t::string>
{
    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, const typename BasicJsonType::string_t& s)
    {
        j.m_type = value_t::string;
        j.m_value = s;
        j.assert_invariant();
    }

    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, typename BasicJsonType::string_t&& s)
    {
        j.m_type = value_t::string;
        j.m_value = std::move(s);
        j.assert_invariant();
    }

    template<typename BasicJsonType, typename CompatibleStringType,
             enable_if_t<not std::is_same<CompatibleStringType, typename BasicJsonType::string_t>::value,
                         int> = 0>
    static void construct(BasicJsonType& j, const CompatibleStringType& str)
    {
        j.m_type = value_t::string;
        j.m_value.string = j.template create<typename BasicJsonType::string_t>(str);
        j.assert_invariant();
    }
};

template<>
struct external_constructor<value_t::number_float>
{
    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, typename BasicJsonType::number_float_t val) noexcept
    {
        j.m_type = value_t::number_float;
        j.m_value = val;
        j.assert_invariant();
    }
};

template<>
struct external_constructor<value_t::number_unsigned>
{
    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, typename BasicJsonType::number_unsigned_t val) noexcept
    {
        j.m_type = value_t::number_unsigned;
        j.m_value = val;
        j.assert_invariant();
    }
};

template<>
struct external_constructor<value_t::number_integer>
{
    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, typename BasicJsonType::number_integer_t val) noexcept
    {
        j.m_type = value_t::number_integer;
        j.m_value = val;
        j.assert_invariant();
    }
};

template<>
struct external_constructor<value_t::array>
{
    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, const typename BasicJsonType::array_t& arr)
    {
        j.m_type = value_t::array;
        j.m_value = arr;
        j.assert_invariant();
    }

    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, typename BasicJsonType::array_t&& arr)
    {
        j.m_type = value_t::array;
        j.m_value = std::move(arr);
        j.assert_invariant();
    }

    template<typename BasicJsonType, typename CompatibleArrayType,
             enable_if_t<not std::is_same<CompatibleArrayType, typename BasicJsonType::array_t>::value,
                         int> = 0>
    static void construct(BasicJsonType& j, const CompatibleArrayType& arr)
    {
        using std::begin;
        using std::end;
        j.m_type = value_t::array;
        j.m_value.array = j.template create<typename BasicJsonType::array_t>(begin(arr), end(arr));
        j.assert_invariant();
    }

    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, const std::vector<bool>& arr)
    {
        j.m_type = value_t::array;
        j.m_value = value_t::array;
        j.m_value.array->reserve(arr.size());
        for (const bool x : arr)
        {
            j.m_value.array->push_back(x);
        }
        j.assert_invariant();
    }

    template<typename BasicJsonType, typename T,
             enable_if_t<std::is_convertible<T, BasicJsonType>::value, int> = 0>
    static void construct(BasicJsonType& j, const std::valarray<T>& arr)
    {
        j.m_type = value_t::array;
        j.m_value = value_t::array;
        j.m_value.array->resize(arr.size());
        std::copy(std::begin(arr), std::end(arr), j.m_value.array->begin());
        j.assert_invariant();
    }
};

template<>
struct external_constructor<value_t::object>
{
    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, const typename BasicJsonType::object_t& obj)
    {
        j.m_type = value_t::object;
        j.m_value = obj;
        j.assert_invariant();
    }

    template<typename BasicJsonType>
    static void construct(BasicJsonType& j, typename BasicJsonType::object_t&& obj)
    {
        j.m_type = value_t::object;
        j.m_value = std::move(obj);
        j.assert_invariant();
    }

    template<typename BasicJsonType, typename CompatibleObjectType,
             enable_if_t<not std::is_same<CompatibleObjectType, typename BasicJsonType::object_t>::value, int> = 0>
    static void construct(BasicJsonType& j, const CompatibleObjectType& obj)
    {
        using std::begin;
        using std::end;

        j.m_type = value_t::object;
        j.m_value.object = j.template create<typename BasicJsonType::object_t>(begin(obj), end(obj));
        j.assert_invariant();
    }
};

template<typename BasicJsonType, typename T,
         enable_if_t<std::is_same<T, typename BasicJsonType::boolean_t>::value, int> = 0>
void to_json(BasicJsonType& j, T b) noexcept
{
    external_constructor<value_t::boolean>::construct(j, b);
}

template<typename BasicJsonType, typename CompatibleString,
         enable_if_t<std::is_constructible<typename BasicJsonType::string_t, CompatibleString>::value, int> = 0>
void to_json(BasicJsonType& j, const CompatibleString& s)
{
    external_constructor<value_t::string>::construct(j, s);
}

template<typename BasicJsonType>
void to_json(BasicJsonType& j, typename BasicJsonType::string_t&& s)
{
    external_constructor<value_t::string>::construct(j, std::move(s));
}

template<typename BasicJsonType, typename FloatType,
         enable_if_t<std::is_floating_point<FloatType>::value, int> = 0>
void to_json(BasicJsonType& j, FloatType val) noexcept
{
    external_constructor<value_t::number_float>::construct(j, static_cast<typename BasicJsonType::number_float_t>(val));
}

template<typename BasicJsonType, typename CompatibleNumberUnsignedType,
         enable_if_t<is_compatible_integer_type<typename BasicJsonType::number_unsigned_t, CompatibleNumberUnsignedType>::value, int> = 0>
void to_json(BasicJsonType& j, CompatibleNumberUnsignedType val) noexcept
{
    external_constructor<value_t::number_unsigned>::construct(j, static_cast<typename BasicJsonType::number_unsigned_t>(val));
}

template<typename BasicJsonType, typename CompatibleNumberIntegerType,
         enable_if_t<is_compatible_integer_type<typename BasicJsonType::number_integer_t, CompatibleNumberIntegerType>::value, int> = 0>
void to_json(BasicJsonType& j, CompatibleNumberIntegerType val) noexcept
{
    external_constructor<value_t::number_integer>::construct(j, static_cast<typename BasicJsonType::number_integer_t>(val));
}

template<typename BasicJsonType, typename EnumType,
         enable_if_t<std::is_enum<EnumType>::value, int> = 0>
void to_json(BasicJsonType& j, EnumType e) noexcept
{
    using underlying_type = typename std::underlying_type<EnumType>::type;
    external_constructor<value_t::number_integer>::construct(j, static_cast<underlying_type>(e));
}

template<typename BasicJsonType>
void to_json(BasicJsonType& j, const std::vector<bool>& e)
{
    external_constructor<value_t::array>::construct(j, e);
}

template<typename BasicJsonType, typename CompatibleArrayType,
         enable_if_t<is_compatible_array_type<BasicJsonType, CompatibleArrayType>::value or
                     std::is_same<typename BasicJsonType::array_t, CompatibleArrayType>::value,
                     int> = 0>
void to_json(BasicJsonType& j, const CompatibleArrayType& arr)
{
    external_constructor<value_t::array>::construct(j, arr);
}

template<typename BasicJsonType, typename T,
         enable_if_t<std::is_convertible<T, BasicJsonType>::value, int> = 0>
void to_json(BasicJsonType& j, const std::valarray<T>& arr)
{
    external_constructor<value_t::array>::construct(j, std::move(arr));
}

template<typename BasicJsonType>
void to_json(BasicJsonType& j, typename BasicJsonType::array_t&& arr)
{
    external_constructor<value_t::array>::construct(j, std::move(arr));
}

template<typename BasicJsonType, typename CompatibleObjectType,
         enable_if_t<is_compatible_object_type<BasicJsonType, CompatibleObjectType>::value, int> = 0>
void to_json(BasicJsonType& j, const CompatibleObjectType& obj)
{
    external_constructor<value_t::object>::construct(j, obj);
}

template<typename BasicJsonType>
void to_json(BasicJsonType& j, typename BasicJsonType::object_t&& obj)
{
    external_constructor<value_t::object>::construct(j, std::move(obj));
}

template<typename BasicJsonType, typename T, std::size_t N,
         enable_if_t<not std::is_constructible<typename BasicJsonType::string_t, T (&)[N]>::value, int> = 0>
void to_json(BasicJsonType& j, T (&arr)[N])
{
    external_constructor<value_t::array>::construct(j, arr);
}

template<typename BasicJsonType, typename... Args>
void to_json(BasicJsonType& j, const std::pair<Args...>& p)
{
    j = {p.first, p.second};
}

template<typename BasicJsonType, typename T,
         enable_if_t<std::is_same<T, typename iteration_proxy<typename BasicJsonType::iterator>::iteration_proxy_internal>::value, int> = 0>
void to_json(BasicJsonType& j, T b) noexcept
{
    j = {{b.key(), b.value()}};
}

template<typename BasicJsonType, typename Tuple, std::size_t... Idx>
void to_json_tuple_impl(BasicJsonType& j, const Tuple& t, index_sequence<Idx...>)
{
    j = {std::get<Idx>(t)...};
}

template<typename BasicJsonType, typename... Args>
void to_json(BasicJsonType& j, const std::tuple<Args...>& t)
{
    to_json_tuple_impl(j, t, index_sequence_for<Args...> {});
}

struct to_json_fn
{
  private:
    template<typename BasicJsonType, typename T>
    auto call(BasicJsonType& j, T&& val, priority_tag<1> ) const noexcept(noexcept(to_json(j, std::forward<T>(val))))
    -> decltype(to_json(j, std::forward<T>(val)), void())
    {
        return to_json(j, std::forward<T>(val));
    }

    template<typename BasicJsonType, typename T>
    void call(BasicJsonType& , T&& , priority_tag<0> ) const noexcept
    {
        static_assert(sizeof(BasicJsonType) == 0,
                      "could not find to_json() method in T's namespace");

#ifdef _MSC_VER
        using decayed = uncvref_t<T>;
        static_assert(sizeof(typename decayed::force_msvc_stacktrace) == 0,
                      "forcing MSVC stacktrace to show which T we're talking about.");
#endif
    }

  public:
    template<typename BasicJsonType, typename T>
    void operator()(BasicJsonType& j, T&& val) const
    noexcept(noexcept(std::declval<to_json_fn>().call(j, std::forward<T>(val), priority_tag<1> {})))
    {
        return call(j, std::forward<T>(val), priority_tag<1> {});
    }
};
}

namespace
{
constexpr const auto& to_json = detail::static_const<detail::to_json_fn>::value;
}
}


#include <cassert>  
#include <cstddef>  
#include <cstring>  
#include <istream>  
#include <iterator>       
#include <memory>    
#include <numeric>  
#include <string>   
#include <type_traits>      
#include <utility>   


namespace nlohmann
{
namespace detail
{
enum class input_format_t { json, cbor, msgpack, ubjson };

struct input_adapter_protocol
{
    virtual std::char_traits<char>::int_type get_character() = 0;
    virtual ~input_adapter_protocol() = default;
};

using input_adapter_t = std::shared_ptr<input_adapter_protocol>;

class input_stream_adapter : public input_adapter_protocol
{
  public:
    ~input_stream_adapter() override
    {
        is.clear();
    }

    explicit input_stream_adapter(std::istream& i)
        : is(i), sb(*i.rdbuf())
    {}

    input_stream_adapter(const input_stream_adapter&) = delete;
    input_stream_adapter& operator=(input_stream_adapter&) = delete;

    std::char_traits<char>::int_type get_character() override
    {
        return sb.sbumpc();
    }

  private:
    std::istream& is;
    std::streambuf& sb;
};

class input_buffer_adapter : public input_adapter_protocol
{
  public:
    input_buffer_adapter(const char* b, const std::size_t l)
        : cursor(b), limit(b + l)
    {}

    input_buffer_adapter(const input_buffer_adapter&) = delete;
    input_buffer_adapter& operator=(input_buffer_adapter&) = delete;

    std::char_traits<char>::int_type get_character() noexcept override
    {
        if (JSON_LIKELY(cursor < limit))
        {
            return std::char_traits<char>::to_int_type(*(cursor++));
        }

        return std::char_traits<char>::eof();
    }

  private:
    const char* cursor;
    const char* const limit;
};

template<typename WideStringType>
class wide_string_input_adapter : public input_adapter_protocol
{
  public:
    explicit wide_string_input_adapter(const WideStringType& w) : str(w) {}

    std::char_traits<char>::int_type get_character() noexcept override
    {
        if (utf8_bytes_index == utf8_bytes_filled)
        {
            if (sizeof(typename WideStringType::value_type) == 2)
            {
                fill_buffer_utf16();
            }
            else
            {
                fill_buffer_utf32();
            }

            assert(utf8_bytes_filled > 0);
            assert(utf8_bytes_index == 0);
        }

        assert(utf8_bytes_filled > 0);
        assert(utf8_bytes_index < utf8_bytes_filled);
        return utf8_bytes[utf8_bytes_index++];
    }

  private:
    void fill_buffer_utf16()
    {
        utf8_bytes_index = 0;

        if (current_wchar == str.size())
        {
            utf8_bytes[0] = std::char_traits<char>::eof();
            utf8_bytes_filled = 1;
        }
        else
        {
            const int wc = static_cast<int>(str[current_wchar++]);

            if (wc < 0x80)
            {
                utf8_bytes[0] = wc;
                utf8_bytes_filled = 1;
            }
            else if (wc <= 0x7FF)
            {
                utf8_bytes[0] = 0xC0 | ((wc >> 6));
                utf8_bytes[1] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 2;
            }
            else if (0xD800 > wc or wc >= 0xE000)
            {
                utf8_bytes[0] = 0xE0 | ((wc >> 12));
                utf8_bytes[1] = 0x80 | ((wc >> 6) & 0x3F);
                utf8_bytes[2] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 3;
            }
            else
            {
                if (current_wchar < str.size())
                {
                    const int wc2 = static_cast<int>(str[current_wchar++]);
                    const int charcode = 0x10000 + (((wc & 0x3FF) << 10) | (wc2 & 0x3FF));
                    utf8_bytes[0] = 0xf0 | (charcode >> 18);
                    utf8_bytes[1] = 0x80 | ((charcode >> 12) & 0x3F);
                    utf8_bytes[2] = 0x80 | ((charcode >> 6) & 0x3F);
                    utf8_bytes[3] = 0x80 | (charcode & 0x3F);
                    utf8_bytes_filled = 4;
                }
                else
                {
                    ++current_wchar;
                    utf8_bytes[0] = wc;
                    utf8_bytes_filled = 1;
                }
            }
        }
    }

    void fill_buffer_utf32()
    {
        utf8_bytes_index = 0;

        if (current_wchar == str.size())
        {
            utf8_bytes[0] = std::char_traits<char>::eof();
            utf8_bytes_filled = 1;
        }
        else
        {
            const int wc = static_cast<int>(str[current_wchar++]);

            if (wc < 0x80)
            {
                utf8_bytes[0] = wc;
                utf8_bytes_filled = 1;
            }
            else if (wc <= 0x7FF)
            {
                utf8_bytes[0] = 0xC0 | ((wc >> 6) & 0x1F);
                utf8_bytes[1] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 2;
            }
            else if (wc <= 0xFFFF)
            {
                utf8_bytes[0] = 0xE0 | ((wc >> 12) & 0x0F);
                utf8_bytes[1] = 0x80 | ((wc >> 6) & 0x3F);
                utf8_bytes[2] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 3;
            }
            else if (wc <= 0x10FFFF)
            {
                utf8_bytes[0] = 0xF0 | ((wc >> 18 ) & 0x07);
                utf8_bytes[1] = 0x80 | ((wc >> 12) & 0x3F);
                utf8_bytes[2] = 0x80 | ((wc >> 6) & 0x3F);
                utf8_bytes[3] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 4;
            }
            else
            {
                utf8_bytes[0] = wc;
                utf8_bytes_filled = 1;
            }
        }
    }

  private:
    const WideStringType& str;

    std::size_t current_wchar = 0;

    std::array<std::char_traits<char>::int_type, 4> utf8_bytes = {{0, 0, 0, 0}};

    std::size_t utf8_bytes_index = 0;
    std::size_t utf8_bytes_filled = 0;
};

class input_adapter
{
  public:
    input_adapter(std::istream& i)
        : ia(std::make_shared<input_stream_adapter>(i)) {}

    input_adapter(std::istream&& i)
        : ia(std::make_shared<input_stream_adapter>(i)) {}

    input_adapter(const std::wstring& ws)
        : ia(std::make_shared<wide_string_input_adapter<std::wstring>>(ws)) {}

    input_adapter(const std::u16string& ws)
        : ia(std::make_shared<wide_string_input_adapter<std::u16string>>(ws)) {}

    input_adapter(const std::u32string& ws)
        : ia(std::make_shared<wide_string_input_adapter<std::u32string>>(ws)) {}

    template<typename CharT,
             typename std::enable_if<
                 std::is_pointer<CharT>::value and
                 std::is_integral<typename std::remove_pointer<CharT>::type>::value and
                 sizeof(typename std::remove_pointer<CharT>::type) == 1,
                 int>::type = 0>
    input_adapter(CharT b, std::size_t l)
        : ia(std::make_shared<input_buffer_adapter>(reinterpret_cast<const char*>(b), l)) {}

    template<typename CharT,
             typename std::enable_if<
                 std::is_pointer<CharT>::value and
                 std::is_integral<typename std::remove_pointer<CharT>::type>::value and
                 sizeof(typename std::remove_pointer<CharT>::type) == 1,
                 int>::type = 0>
    input_adapter(CharT b)
        : input_adapter(reinterpret_cast<const char*>(b),
                        std::strlen(reinterpret_cast<const char*>(b))) {}

    template<class IteratorType,
             typename std::enable_if<
                 std::is_same<typename std::iterator_traits<IteratorType>::iterator_category, std::random_access_iterator_tag>::value,
                 int>::type = 0>
    input_adapter(IteratorType first, IteratorType last)
    {
        assert(std::accumulate(
                   first, last, std::pair<bool, int>(true, 0),
                   [&first](std::pair<bool, int> res, decltype(*first) val)
        {
            res.first &= (val == *(std::next(std::addressof(*first), res.second++)));
            return res;
        }).first);

        static_assert(
            sizeof(typename std::iterator_traits<IteratorType>::value_type) == 1,
            "each element in the iterator range must have the size of 1 byte");

        const auto len = static_cast<size_t>(std::distance(first, last));
        if (JSON_LIKELY(len > 0))
        {
            ia = std::make_shared<input_buffer_adapter>(reinterpret_cast<const char*>(&(*first)), len);
        }
        else
        {
            ia = std::make_shared<input_buffer_adapter>(nullptr, len);
        }
    }

    template<class T, std::size_t N>
    input_adapter(T (&array)[N])
        : input_adapter(std::begin(array), std::end(array)) {}

    template<class ContiguousContainer, typename
             std::enable_if<not std::is_pointer<ContiguousContainer>::value and
                            std::is_base_of<std::random_access_iterator_tag, typename std::iterator_traits<decltype(std::begin(std::declval<ContiguousContainer const>()))>::iterator_category>::value,
                            int>::type = 0>
    input_adapter(const ContiguousContainer& c)
        : input_adapter(std::begin(c), std::end(c)) {}

    operator input_adapter_t()
    {
        return ia;
    }

  private:
    input_adapter_t ia = nullptr;
};
}
}


#include <clocale>  
#include <cstddef>  
#include <cstdlib>      
#include <cstdio>  
#include <initializer_list>  
#include <string>   
#include <vector>  


namespace nlohmann
{
namespace detail
{
template<typename BasicJsonType>
class lexer
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;

  public:
    enum class token_type
    {
        uninitialized,         
        literal_true,        
        literal_false,       
        literal_null,        
        value_string,             
        value_unsigned,            
        value_integer,             
        value_float,                
        begin_array,            
        begin_object,           
        end_array,              
        end_object,             
        name_separator,       
        value_separator,      
        parse_error,          
        end_of_input,            
        literal_or_value             
    };

    static const char* token_type_name(const token_type t) noexcept
    {
        switch (t)
        {
            case token_type::uninitialized:
                return "<uninitialized>";
            case token_type::literal_true:
                return "true literal";
            case token_type::literal_false:
                return "false literal";
            case token_type::literal_null:
                return "null literal";
            case token_type::value_string:
                return "string literal";
            case lexer::token_type::value_unsigned:
            case lexer::token_type::value_integer:
            case lexer::token_type::value_float:
                return "number literal";
            case token_type::begin_array:
                return "'['";
            case token_type::begin_object:
                return "'{'";
            case token_type::end_array:
                return "']'";
            case token_type::end_object:
                return "'}'";
            case token_type::name_separator:
                return "':'";
            case token_type::value_separator:
                return "','";
            case token_type::parse_error:
                return "<parse error>";
            case token_type::end_of_input:
                return "end of input";
            case token_type::literal_or_value:
                return "'[', '{', or a literal";
            default:    
                return "unknown token";
        }
    }

    explicit lexer(detail::input_adapter_t&& adapter)
        : ia(std::move(adapter)), decimal_point_char(get_decimal_point()) {}

    lexer(const lexer&) = delete;
    lexer& operator=(lexer&) = delete;

  private:
    static char get_decimal_point() noexcept
    {
        const auto loc = localeconv();
        assert(loc != nullptr);
        return (loc->decimal_point == nullptr) ? '.' : *(loc->decimal_point);
    }

    int get_codepoint()
    {
        assert(current == 'u');
        int codepoint = 0;

        const auto factors = { 12, 8, 4, 0 };
        for (const auto factor : factors)
        {
            get();

            if (current >= '0' and current <= '9')
            {
                codepoint += ((current - 0x30) << factor);
            }
            else if (current >= 'A' and current <= 'F')
            {
                codepoint += ((current - 0x37) << factor);
            }
            else if (current >= 'a' and current <= 'f')
            {
                codepoint += ((current - 0x57) << factor);
            }
            else
            {
                return -1;
            }
        }

        assert(0x0000 <= codepoint and codepoint <= 0xFFFF);
        return codepoint;
    }

    bool next_byte_in_range(std::initializer_list<int> ranges)
    {
        assert(ranges.size() == 2 or ranges.size() == 4 or ranges.size() == 6);
        add(current);

        for (auto range = ranges.begin(); range != ranges.end(); ++range)
        {
            get();
            if (JSON_LIKELY(*range <= current and current <= *(++range)))
            {
                add(current);
            }
            else
            {
                error_message = "invalid string: ill-formed UTF-8 byte";
                return false;
            }
        }

        return true;
    }

    token_type scan_string()
    {
        reset();

        assert(current == '\"');

        while (true)
        {
            switch (get())
            {
                case std::char_traits<char>::eof():
                {
                    error_message = "invalid string: missing closing quote";
                    return token_type::parse_error;
                }

                case '\"':
                {
                    return token_type::value_string;
                }

                case '\\':
                {
                    switch (get())
                    {
                        case '\"':
                            add('\"');
                            break;
                        case '\\':
                            add('\\');
                            break;
                        case '/':
                            add('/');
                            break;
                        case 'b':
                            add('\b');
                            break;
                        case 'f':
                            add('\f');
                            break;
                        case 'n':
                            add('\n');
                            break;
                        case 'r':
                            add('\r');
                            break;
                        case 't':
                            add('\t');
                            break;

                        case 'u':
                        {
                            const int codepoint1 = get_codepoint();
                            int codepoint = codepoint1;    

                            if (JSON_UNLIKELY(codepoint1 == -1))
                            {
                                error_message = "invalid string: '\\u' must be followed by 4 hex digits";
                                return token_type::parse_error;
                            }

                            if (0xD800 <= codepoint1 and codepoint1 <= 0xDBFF)
                            {
                                if (JSON_LIKELY(get() == '\\' and get() == 'u'))
                                {
                                    const int codepoint2 = get_codepoint();

                                    if (JSON_UNLIKELY(codepoint2 == -1))
                                    {
                                        error_message = "invalid string: '\\u' must be followed by 4 hex digits";
                                        return token_type::parse_error;
                                    }

                                    if (JSON_LIKELY(0xDC00 <= codepoint2 and codepoint2 <= 0xDFFF))
                                    {
                                        codepoint =
                                            (codepoint1 << 10)
                                            + codepoint2
                                            - 0x35FDC00;
                                    }
                                    else
                                    {
                                        error_message = "invalid string: surrogate U+DC00..U+DFFF must be followed by U+DC00..U+DFFF";
                                        return token_type::parse_error;
                                    }
                                }
                                else
                                {
                                    error_message = "invalid string: surrogate U+DC00..U+DFFF must be followed by U+DC00..U+DFFF";
                                    return token_type::parse_error;
                                }
                            }
                            else
                            {
                                if (JSON_UNLIKELY(0xDC00 <= codepoint1 and codepoint1 <= 0xDFFF))
                                {
                                    error_message = "invalid string: surrogate U+DC00..U+DFFF must follow U+D800..U+DBFF";
                                    return token_type::parse_error;
                                }
                            }

                            assert(0x00 <= codepoint and codepoint <= 0x10FFFF);

                            if (codepoint < 0x80)
                            {
                                add(codepoint);
                            }
                            else if (codepoint <= 0x7FF)
                            {
                                add(0xC0 | (codepoint >> 6));
                                add(0x80 | (codepoint & 0x3F));
                            }
                            else if (codepoint <= 0xFFFF)
                            {
                                add(0xE0 | (codepoint >> 12));
                                add(0x80 | ((codepoint >> 6) & 0x3F));
                                add(0x80 | (codepoint & 0x3F));
                            }
                            else
                            {
                                add(0xF0 | (codepoint >> 18));
                                add(0x80 | ((codepoint >> 12) & 0x3F));
                                add(0x80 | ((codepoint >> 6) & 0x3F));
                                add(0x80 | (codepoint & 0x3F));
                            }

                            break;
                        }

                        default:
                            error_message = "invalid string: forbidden character after backslash";
                            return token_type::parse_error;
                    }

                    break;
                }

                case 0x00:
                case 0x01:
                case 0x02:
                case 0x03:
                case 0x04:
                case 0x05:
                case 0x06:
                case 0x07:
                case 0x08:
                case 0x09:
                case 0x0A:
                case 0x0B:
                case 0x0C:
                case 0x0D:
                case 0x0E:
                case 0x0F:
                case 0x10:
                case 0x11:
                case 0x12:
                case 0x13:
                case 0x14:
                case 0x15:
                case 0x16:
                case 0x17:
                case 0x18:
                case 0x19:
                case 0x1A:
                case 0x1B:
                case 0x1C:
                case 0x1D:
                case 0x1E:
                case 0x1F:
                {
                    error_message = "invalid string: control character must be escaped";
                    return token_type::parse_error;
                }

                case 0x20:
                case 0x21:
                case 0x23:
                case 0x24:
                case 0x25:
                case 0x26:
                case 0x27:
                case 0x28:
                case 0x29:
                case 0x2A:
                case 0x2B:
                case 0x2C:
                case 0x2D:
                case 0x2E:
                case 0x2F:
                case 0x30:
                case 0x31:
                case 0x32:
                case 0x33:
                case 0x34:
                case 0x35:
                case 0x36:
                case 0x37:
                case 0x38:
                case 0x39:
                case 0x3A:
                case 0x3B:
                case 0x3C:
                case 0x3D:
                case 0x3E:
                case 0x3F:
                case 0x40:
                case 0x41:
                case 0x42:
                case 0x43:
                case 0x44:
                case 0x45:
                case 0x46:
                case 0x47:
                case 0x48:
                case 0x49:
                case 0x4A:
                case 0x4B:
                case 0x4C:
                case 0x4D:
                case 0x4E:
                case 0x4F:
                case 0x50:
                case 0x51:
                case 0x52:
                case 0x53:
                case 0x54:
                case 0x55:
                case 0x56:
                case 0x57:
                case 0x58:
                case 0x59:
                case 0x5A:
                case 0x5B:
                case 0x5D:
                case 0x5E:
                case 0x5F:
                case 0x60:
                case 0x61:
                case 0x62:
                case 0x63:
                case 0x64:
                case 0x65:
                case 0x66:
                case 0x67:
                case 0x68:
                case 0x69:
                case 0x6A:
                case 0x6B:
                case 0x6C:
                case 0x6D:
                case 0x6E:
                case 0x6F:
                case 0x70:
                case 0x71:
                case 0x72:
                case 0x73:
                case 0x74:
                case 0x75:
                case 0x76:
                case 0x77:
                case 0x78:
                case 0x79:
                case 0x7A:
                case 0x7B:
                case 0x7C:
                case 0x7D:
                case 0x7E:
                case 0x7F:
                {
                    add(current);
                    break;
                }

                case 0xC2:
                case 0xC3:
                case 0xC4:
                case 0xC5:
                case 0xC6:
                case 0xC7:
                case 0xC8:
                case 0xC9:
                case 0xCA:
                case 0xCB:
                case 0xCC:
                case 0xCD:
                case 0xCE:
                case 0xCF:
                case 0xD0:
                case 0xD1:
                case 0xD2:
                case 0xD3:
                case 0xD4:
                case 0xD5:
                case 0xD6:
                case 0xD7:
                case 0xD8:
                case 0xD9:
                case 0xDA:
                case 0xDB:
                case 0xDC:
                case 0xDD:
                case 0xDE:
                case 0xDF:
                {
                    if (JSON_UNLIKELY(not next_byte_in_range({0x80, 0xBF})))
                    {
                        return token_type::parse_error;
                    }
                    break;
                }

                case 0xE0:
                {
                    if (JSON_UNLIKELY(not (next_byte_in_range({0xA0, 0xBF, 0x80, 0xBF}))))
                    {
                        return token_type::parse_error;
                    }
                    break;
                }

                case 0xE1:
                case 0xE2:
                case 0xE3:
                case 0xE4:
                case 0xE5:
                case 0xE6:
                case 0xE7:
                case 0xE8:
                case 0xE9:
                case 0xEA:
                case 0xEB:
                case 0xEC:
                case 0xEE:
                case 0xEF:
                {
                    if (JSON_UNLIKELY(not (next_byte_in_range({0x80, 0xBF, 0x80, 0xBF}))))
                    {
                        return token_type::parse_error;
                    }
                    break;
                }

                case 0xED:
                {
                    if (JSON_UNLIKELY(not (next_byte_in_range({0x80, 0x9F, 0x80, 0xBF}))))
                    {
                        return token_type::parse_error;
                    }
                    break;
                }

                case 0xF0:
                {
                    if (JSON_UNLIKELY(not (next_byte_in_range({0x90, 0xBF, 0x80, 0xBF, 0x80, 0xBF}))))
                    {
                        return token_type::parse_error;
                    }
                    break;
                }

                case 0xF1:
                case 0xF2:
                case 0xF3:
                {
                    if (JSON_UNLIKELY(not (next_byte_in_range({0x80, 0xBF, 0x80, 0xBF, 0x80, 0xBF}))))
                    {
                        return token_type::parse_error;
                    }
                    break;
                }

                case 0xF4:
                {
                    if (JSON_UNLIKELY(not (next_byte_in_range({0x80, 0x8F, 0x80, 0xBF, 0x80, 0xBF}))))
                    {
                        return token_type::parse_error;
                    }
                    break;
                }

                default:
                {
                    error_message = "invalid string: ill-formed UTF-8 byte";
                    return token_type::parse_error;
                }
            }
        }
    }

    static void strtof(float& f, const char* str, char** endptr) noexcept
    {
        f = std::strtof(str, endptr);
    }

    static void strtof(double& f, const char* str, char** endptr) noexcept
    {
        f = std::strtod(str, endptr);
    }

    static void strtof(long double& f, const char* str, char** endptr) noexcept
    {
        f = std::strtold(str, endptr);
    }

    token_type scan_number()
    {
        reset();

        token_type number_type = token_type::value_unsigned;

        switch (current)
        {
            case '-':
            {
                add(current);
                goto scan_number_minus;
            }

            case '0':
            {
                add(current);
                goto scan_number_zero;
            }

            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            {
                add(current);
                goto scan_number_any1;
            }

            default:
            {
                assert(false);
            }
        }

scan_number_minus:
        number_type = token_type::value_integer;
        switch (get())
        {
            case '0':
            {
                add(current);
                goto scan_number_zero;
            }

            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            {
                add(current);
                goto scan_number_any1;
            }

            default:
            {
                error_message = "invalid number; expected digit after '-'";
                return token_type::parse_error;
            }
        }

scan_number_zero:
        switch (get())
        {
            case '.':
            {
                add(decimal_point_char);
                goto scan_number_decimal1;
            }

            case 'e':
            case 'E':
            {
                add(current);
                goto scan_number_exponent;
            }

            default:
                goto scan_number_done;
        }

scan_number_any1:
        switch (get())
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            {
                add(current);
                goto scan_number_any1;
            }

            case '.':
            {
                add(decimal_point_char);
                goto scan_number_decimal1;
            }

            case 'e':
            case 'E':
            {
                add(current);
                goto scan_number_exponent;
            }

            default:
                goto scan_number_done;
        }

scan_number_decimal1:
        number_type = token_type::value_float;
        switch (get())
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            {
                add(current);
                goto scan_number_decimal2;
            }

            default:
            {
                error_message = "invalid number; expected digit after '.'";
                return token_type::parse_error;
            }
        }

scan_number_decimal2:
        switch (get())
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            {
                add(current);
                goto scan_number_decimal2;
            }

            case 'e':
            case 'E':
            {
                add(current);
                goto scan_number_exponent;
            }

            default:
                goto scan_number_done;
        }

scan_number_exponent:
        number_type = token_type::value_float;
        switch (get())
        {
            case '+':
            case '-':
            {
                add(current);
                goto scan_number_sign;
            }

            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            {
                add(current);
                goto scan_number_any2;
            }

            default:
            {
                error_message =
                    "invalid number; expected '+', '-', or digit after exponent";
                return token_type::parse_error;
            }
        }

scan_number_sign:
        switch (get())
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            {
                add(current);
                goto scan_number_any2;
            }

            default:
            {
                error_message = "invalid number; expected digit after exponent sign";
                return token_type::parse_error;
            }
        }

scan_number_any2:
        switch (get())
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            {
                add(current);
                goto scan_number_any2;
            }

            default:
                goto scan_number_done;
        }

scan_number_done:
        unget();

        char* endptr = nullptr;
        errno = 0;

        if (number_type == token_type::value_unsigned)
        {
            const auto x = std::strtoull(token_buffer.data(), &endptr, 10);

            assert(endptr == token_buffer.data() + token_buffer.size());

            if (errno == 0)
            {
                value_unsigned = static_cast<number_unsigned_t>(x);
                if (value_unsigned == x)
                {
                    return token_type::value_unsigned;
                }
            }
        }
        else if (number_type == token_type::value_integer)
        {
            const auto x = std::strtoll(token_buffer.data(), &endptr, 10);

            assert(endptr == token_buffer.data() + token_buffer.size());

            if (errno == 0)
            {
                value_integer = static_cast<number_integer_t>(x);
                if (value_integer == x)
                {
                    return token_type::value_integer;
                }
            }
        }

        strtof(value_float, token_buffer.data(), &endptr);

        assert(endptr == token_buffer.data() + token_buffer.size());

        return token_type::value_float;
    }

    token_type scan_literal(const char* literal_text, const std::size_t length,
                            token_type return_type)
    {
        assert(current == literal_text[0]);
        for (std::size_t i = 1; i < length; ++i)
        {
            if (JSON_UNLIKELY(get() != literal_text[i]))
            {
                error_message = "invalid literal";
                return token_type::parse_error;
            }
        }
        return return_type;
    }

    void reset() noexcept
    {
        token_buffer.clear();
        token_string.clear();
        token_string.push_back(std::char_traits<char>::to_char_type(current));
    }

    std::char_traits<char>::int_type get()
    {
        ++chars_read;
        if (next_unget)
        {
            next_unget = false;
        }
        else
        {
            current = ia->get_character();
        }

        if (JSON_LIKELY(current != std::char_traits<char>::eof()))
        {
            token_string.push_back(std::char_traits<char>::to_char_type(current));
        }
        return current;
    }

    void unget()
    {
        next_unget = true;
        --chars_read;
        if (JSON_LIKELY(current != std::char_traits<char>::eof()))
        {
            assert(token_string.size() != 0);
            token_string.pop_back();
        }
    }

    void add(int c)
    {
        token_buffer.push_back(std::char_traits<char>::to_char_type(c));
    }

  public:
    constexpr number_integer_t get_number_integer() const noexcept
    {
        return value_integer;
    }

    constexpr number_unsigned_t get_number_unsigned() const noexcept
    {
        return value_unsigned;
    }

    constexpr number_float_t get_number_float() const noexcept
    {
        return value_float;
    }

    string_t& get_string()
    {
        return token_buffer;
    }

    constexpr std::size_t get_position() const noexcept
    {
        return chars_read;
    }

    std::string get_token_string() const
    {
        std::string result;
        for (const auto c : token_string)
        {
            if ('\x00' <= c and c <= '\x1F')
            {
                char cs[9];
                snprintf(cs, 9, "<U+%.4X>", static_cast<unsigned char>(c));
                result += cs;
            }
            else
            {
                result.push_back(c);
            }
        }

        return result;
    }

    constexpr const char* get_error_message() const noexcept
    {
        return error_message;
    }

    bool skip_bom()
    {
        if (get() == 0xEF)
        {
            if (get() == 0xBB and get() == 0xBF)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            unget();
            return true;
        }
    }

    token_type scan()
    {
        if (chars_read == 0 and not skip_bom())
        {
            error_message = "invalid BOM; must be 0xEF 0xBB 0xBF if given";
            return token_type::parse_error;
        }

        do
        {
            get();
        }
        while (current == ' ' or current == '\t' or current == '\n' or current == '\r');

        switch (current)
        {
            case '[':
                return token_type::begin_array;
            case ']':
                return token_type::end_array;
            case '{':
                return token_type::begin_object;
            case '}':
                return token_type::end_object;
            case ':':
                return token_type::name_separator;
            case ',':
                return token_type::value_separator;

            case 't':
                return scan_literal("true", 4, token_type::literal_true);
            case 'f':
                return scan_literal("false", 5, token_type::literal_false);
            case 'n':
                return scan_literal("null", 4, token_type::literal_null);

            case '\"':
                return scan_string();

            case '-':
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                return scan_number();

            case '\0':
            case std::char_traits<char>::eof():
                return token_type::end_of_input;

            default:
                error_message = "invalid literal";
                return token_type::parse_error;
        }
    }

  private:
    detail::input_adapter_t ia = nullptr;

    std::char_traits<char>::int_type current = std::char_traits<char>::eof();

    bool next_unget = false;

    std::size_t chars_read = 0;

    std::vector<char> token_string {};

    string_t token_buffer {};

    const char* error_message = "";

    number_integer_t value_integer = 0;
    number_unsigned_t value_unsigned = 0;
    number_float_t value_float = 0;

    const char decimal_point_char = '.';
};
}
}


#include <cassert>  
#include <cmath>  
#include <cstdint>  
#include <functional>  
#include <string>  
#include <utility>  


#include <cstdint>  
#include <utility>  


#include <type_traits>


namespace nlohmann
{
namespace detail
{
template <typename...>
using void_t = void;
}
}


namespace nlohmann
{
namespace detail
{
struct nonesuch
{
    nonesuch() = delete;
    ~nonesuch() = delete;
    nonesuch(nonesuch const&) = delete;
    void operator=(nonesuch const&) = delete;
};

template <class Default,
          class AlwaysVoid,
          template <class...> class Op,
          class... Args>
struct detector
{
    using value_t = std::false_type;
    using type = Default;
};

template <class Default, template <class...> class Op, class... Args>
struct detector<Default, void_t<Op<Args...>>, Op, Args...>
{
    using value_t = std::true_type;
    using type = Op<Args...>;
};

template <template <class...> class Op, class... Args>
using is_detected = typename detector<nonesuch, void, Op, Args...>::value_t;

template <template <class...> class Op, class... Args>
using detected_t = typename detector<nonesuch, void, Op, Args...>::type;

template <class Default, template <class...> class Op, class... Args>
using detected_or = detector<Default, void, Op, Args...>;

template <class Default, template <class...> class Op, class... Args>
using detected_or_t = typename detected_or<Default, Op, Args...>::type;

template <class Expected, template <class...> class Op, class... Args>
using is_detected_exact = std::is_same<Expected, detected_t<Op, Args...>>;

template <class To, template <class...> class Op, class... Args>
using is_detected_convertible =
    std::is_convertible<detected_t<Op, Args...>, To>;
}
}


namespace nlohmann
{
namespace detail
{
template <typename T>
using null_function_t = decltype(std::declval<T&>().null());

template <typename T>
using boolean_function_t =
    decltype(std::declval<T&>().boolean(std::declval<bool>()));

template <typename T, typename Integer>
using number_integer_function_t =
    decltype(std::declval<T&>().number_integer(std::declval<Integer>()));

template <typename T, typename Unsigned>
using number_unsigned_function_t =
    decltype(std::declval<T&>().number_unsigned(std::declval<Unsigned>()));

template <typename T, typename Float, typename String>
using number_float_function_t = decltype(std::declval<T&>().number_float(
                                    std::declval<Float>(), std::declval<const String&>()));

template <typename T, typename String>
using string_function_t =
    decltype(std::declval<T&>().string(std::declval<String&>()));

template <typename T>
using start_object_function_t =
    decltype(std::declval<T&>().start_object(std::declval<std::size_t>()));

template <typename T, typename String>
using key_function_t =
    decltype(std::declval<T&>().key(std::declval<String&>()));

template <typename T>
using end_object_function_t = decltype(std::declval<T&>().end_object());

template <typename T>
using start_array_function_t =
    decltype(std::declval<T&>().start_array(std::declval<std::size_t>()));

template <typename T>
using end_array_function_t = decltype(std::declval<T&>().end_array());

template <typename T, typename Exception>
using parse_error_function_t = decltype(std::declval<T&>().parse_error(
        std::declval<std::size_t>(), std::declval<const std::string&>(),
        std::declval<const Exception&>()));

template <typename SAX, typename BasicJsonType>
struct is_sax
{
  private:
    static_assert(is_basic_json<BasicJsonType>::value,
                  "BasicJsonType must be of type basic_json<...>");

    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using exception_t = typename BasicJsonType::exception;

  public:
    static constexpr bool value =
        is_detected_exact<bool, null_function_t, SAX>::value &&
        is_detected_exact<bool, boolean_function_t, SAX>::value &&
        is_detected_exact<bool, number_integer_function_t, SAX,
        number_integer_t>::value &&
        is_detected_exact<bool, number_unsigned_function_t, SAX,
        number_unsigned_t>::value &&
        is_detected_exact<bool, number_float_function_t, SAX, number_float_t,
        string_t>::value &&
        is_detected_exact<bool, string_function_t, SAX, string_t>::value &&
        is_detected_exact<bool, start_object_function_t, SAX>::value &&
        is_detected_exact<bool, key_function_t, SAX, string_t>::value &&
        is_detected_exact<bool, end_object_function_t, SAX>::value &&
        is_detected_exact<bool, start_array_function_t, SAX>::value &&
        is_detected_exact<bool, end_array_function_t, SAX>::value &&
        is_detected_exact<bool, parse_error_function_t, SAX, exception_t>::value;
};

template <typename SAX, typename BasicJsonType>
struct is_sax_static_asserts
{
  private:
    static_assert(is_basic_json<BasicJsonType>::value,
                  "BasicJsonType must be of type basic_json<...>");

    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using exception_t = typename BasicJsonType::exception;

  public:
    static_assert(is_detected_exact<bool, null_function_t, SAX>::value,
                  "Missing/invalid function: bool null()");
    static_assert(is_detected_exact<bool, boolean_function_t, SAX>::value,
                  "Missing/invalid function: bool boolean(bool)");
    static_assert(is_detected_exact<bool, boolean_function_t, SAX>::value,
                  "Missing/invalid function: bool boolean(bool)");
    static_assert(
        is_detected_exact<bool, number_integer_function_t, SAX,
        number_integer_t>::value,
        "Missing/invalid function: bool number_integer(number_integer_t)");
    static_assert(
        is_detected_exact<bool, number_unsigned_function_t, SAX,
        number_unsigned_t>::value,
        "Missing/invalid function: bool number_unsigned(number_unsigned_t)");
    static_assert(is_detected_exact<bool, number_float_function_t, SAX,
                  number_float_t, string_t>::value,
                  "Missing/invalid function: bool number_float(number_float_t, const string_t&)");
    static_assert(
        is_detected_exact<bool, string_function_t, SAX, string_t>::value,
        "Missing/invalid function: bool string(string_t&)");
    static_assert(is_detected_exact<bool, start_object_function_t, SAX>::value,
                  "Missing/invalid function: bool start_object(std::size_t)");
    static_assert(is_detected_exact<bool, key_function_t, SAX, string_t>::value,
                  "Missing/invalid function: bool key(string_t&)");
    static_assert(is_detected_exact<bool, end_object_function_t, SAX>::value,
                  "Missing/invalid function: bool end_object()");
    static_assert(is_detected_exact<bool, start_array_function_t, SAX>::value,
                  "Missing/invalid function: bool start_array(std::size_t)");
    static_assert(is_detected_exact<bool, end_array_function_t, SAX>::value,
                  "Missing/invalid function: bool end_array()");
    static_assert(
        is_detected_exact<bool, parse_error_function_t, SAX, exception_t>::value,
        "Missing/invalid function: bool parse_error(std::size_t, const "
        "std::string&, const exception&)");
};
}
}


#include <cstddef>
#include <string>
#include <vector>


namespace nlohmann
{

template<typename BasicJsonType>
struct json_sax
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;

    virtual bool null() = 0;

    virtual bool boolean(bool val) = 0;

    virtual bool number_integer(number_integer_t val) = 0;

    virtual bool number_unsigned(number_unsigned_t val) = 0;

    virtual bool number_float(number_float_t val, const string_t& s) = 0;

    virtual bool string(string_t& val) = 0;

    virtual bool start_object(std::size_t elements) = 0;

    virtual bool key(string_t& val) = 0;

    virtual bool end_object() = 0;

    virtual bool start_array(std::size_t elements) = 0;

    virtual bool end_array() = 0;

    virtual bool parse_error(std::size_t position,
                             const std::string& last_token,
                             const detail::exception& ex) = 0;

    virtual ~json_sax() = default;
};


namespace detail
{
template<typename BasicJsonType>
class json_sax_dom_parser
{
  public:
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;

    explicit json_sax_dom_parser(BasicJsonType& r, const bool allow_exceptions_ = true)
        : root(r), allow_exceptions(allow_exceptions_)
    {}

    bool null()
    {
        handle_value(nullptr);
        return true;
    }

    bool boolean(bool val)
    {
        handle_value(val);
        return true;
    }

    bool number_integer(number_integer_t val)
    {
        handle_value(val);
        return true;
    }

    bool number_unsigned(number_unsigned_t val)
    {
        handle_value(val);
        return true;
    }

    bool number_float(number_float_t val, const string_t&)
    {
        handle_value(val);
        return true;
    }

    bool string(string_t& val)
    {
        handle_value(val);
        return true;
    }

    bool start_object(std::size_t len)
    {
        ref_stack.push_back(handle_value(BasicJsonType::value_t::object));

        if (JSON_UNLIKELY(len != std::size_t(-1) and len > ref_stack.back()->max_size()))
        {
            JSON_THROW(out_of_range::create(408,
                                            "excessive object size: " + std::to_string(len)));
        }

        return true;
    }

    bool key(string_t& val)
    {
        object_element = &(ref_stack.back()->m_value.object->operator[](val));
        return true;
    }

    bool end_object()
    {
        ref_stack.pop_back();
        return true;
    }

    bool start_array(std::size_t len)
    {
        ref_stack.push_back(handle_value(BasicJsonType::value_t::array));

        if (JSON_UNLIKELY(len != std::size_t(-1) and len > ref_stack.back()->max_size()))
        {
            JSON_THROW(out_of_range::create(408,
                                            "excessive array size: " + std::to_string(len)));
        }

        return true;
    }

    bool end_array()
    {
        ref_stack.pop_back();
        return true;
    }

    bool parse_error(std::size_t, const std::string&,
                     const detail::exception& ex)
    {
        errored = true;
        if (allow_exceptions)
        {
            switch ((ex.id / 100) % 100)
            {
                case 1:
                    JSON_THROW(*reinterpret_cast<const detail::parse_error*>(&ex));
                case 4:
                    JSON_THROW(*reinterpret_cast<const detail::out_of_range*>(&ex));
                case 2:
                    JSON_THROW(*reinterpret_cast<const detail::invalid_iterator*>(&ex));
                case 3:
                    JSON_THROW(*reinterpret_cast<const detail::type_error*>(&ex));
                case 5:
                    JSON_THROW(*reinterpret_cast<const detail::other_error*>(&ex));
                default:
                    assert(false);
            }
        }
        return false;
    }

    constexpr bool is_errored() const
    {
        return errored;
    }

  private:
    template<typename Value>
    BasicJsonType* handle_value(Value&& v)
    {
        if (ref_stack.empty())
        {
            root = BasicJsonType(std::forward<Value>(v));
            return &root;
        }
        else
        {
            assert(ref_stack.back()->is_array() or ref_stack.back()->is_object());
            if (ref_stack.back()->is_array())
            {
                ref_stack.back()->m_value.array->emplace_back(std::forward<Value>(v));
                return &(ref_stack.back()->m_value.array->back());
            }
            else
            {
                assert(object_element);
                *object_element = BasicJsonType(std::forward<Value>(v));
                return object_element;
            }
        }
    }

    BasicJsonType& root;
    std::vector<BasicJsonType*> ref_stack;
    BasicJsonType* object_element = nullptr;
    bool errored = false;
    const bool allow_exceptions = true;
};

template<typename BasicJsonType>
class json_sax_dom_callback_parser
{
  public:
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using parser_callback_t = typename BasicJsonType::parser_callback_t;
    using parse_event_t = typename BasicJsonType::parse_event_t;

    json_sax_dom_callback_parser(BasicJsonType& r,
                                 const parser_callback_t cb,
                                 const bool allow_exceptions_ = true)
        : root(r), callback(cb), allow_exceptions(allow_exceptions_)
    {
        keep_stack.push_back(true);
    }

    bool null()
    {
        handle_value(nullptr);
        return true;
    }

    bool boolean(bool val)
    {
        handle_value(val);
        return true;
    }

    bool number_integer(number_integer_t val)
    {
        handle_value(val);
        return true;
    }

    bool number_unsigned(number_unsigned_t val)
    {
        handle_value(val);
        return true;
    }

    bool number_float(number_float_t val, const string_t&)
    {
        handle_value(val);
        return true;
    }

    bool string(string_t& val)
    {
        handle_value(val);
        return true;
    }

    bool start_object(std::size_t len)
    {
        const bool keep = callback(static_cast<int>(ref_stack.size()), parse_event_t::object_start, discarded);
        keep_stack.push_back(keep);

        auto val = handle_value(BasicJsonType::value_t::object, true);
        ref_stack.push_back(val.second);

        if (ref_stack.back())
        {
            if (JSON_UNLIKELY(len != std::size_t(-1) and len > ref_stack.back()->max_size()))
            {
                JSON_THROW(out_of_range::create(408,
                                                "excessive object size: " + std::to_string(len)));
            }
        }

        return true;
    }

    bool key(string_t& val)
    {
        BasicJsonType k = BasicJsonType(val);

        const bool keep = callback(static_cast<int>(ref_stack.size()), parse_event_t::key, k);
        key_keep_stack.push_back(keep);

        if (keep and ref_stack.back())
        {
            object_element = &(ref_stack.back()->m_value.object->operator[](val) = discarded);
        }

        return true;
    }

    bool end_object()
    {
        if (ref_stack.back())
        {
            if (not callback(static_cast<int>(ref_stack.size()) - 1, parse_event_t::object_end, *ref_stack.back()))
            {
                *ref_stack.back() = discarded;
            }
        }

        assert(not ref_stack.empty());
        assert(not keep_stack.empty());
        ref_stack.pop_back();
        keep_stack.pop_back();

        if (not ref_stack.empty() and ref_stack.back())
        {
            if (ref_stack.back()->is_object())
            {
                for (auto it = ref_stack.back()->begin(); it != ref_stack.back()->end(); ++it)
                {
                    if (it->is_discarded())
                    {
                        ref_stack.back()->erase(it);
                        break;
                    }
                }
            }
        }

        return true;
    }

    bool start_array(std::size_t len)
    {
        const bool keep = callback(static_cast<int>(ref_stack.size()), parse_event_t::array_start, discarded);
        keep_stack.push_back(keep);

        auto val = handle_value(BasicJsonType::value_t::array, true);
        ref_stack.push_back(val.second);

        if (ref_stack.back())
        {
            if (JSON_UNLIKELY(len != std::size_t(-1) and len > ref_stack.back()->max_size()))
            {
                JSON_THROW(out_of_range::create(408,
                                                "excessive array size: " + std::to_string(len)));
            }
        }

        return true;
    }

    bool end_array()
    {
        bool keep = true;

        if (ref_stack.back())
        {
            keep = callback(static_cast<int>(ref_stack.size()) - 1, parse_event_t::array_end, *ref_stack.back());
            if (not keep)
            {
                *ref_stack.back() = discarded;
            }
        }

        assert(not ref_stack.empty());
        assert(not keep_stack.empty());
        ref_stack.pop_back();
        keep_stack.pop_back();

        if (not keep and not ref_stack.empty())
        {
            if (ref_stack.back()->is_array())
            {
                ref_stack.back()->m_value.array->pop_back();
            }
        }

        return true;
    }

    bool parse_error(std::size_t, const std::string&,
                     const detail::exception& ex)
    {
        errored = true;
        if (allow_exceptions)
        {
            switch ((ex.id / 100) % 100)
            {
                case 1:
                    JSON_THROW(*reinterpret_cast<const detail::parse_error*>(&ex));
                case 4:
                    JSON_THROW(*reinterpret_cast<const detail::out_of_range*>(&ex));
                case 2:
                    JSON_THROW(*reinterpret_cast<const detail::invalid_iterator*>(&ex));
                case 3:
                    JSON_THROW(*reinterpret_cast<const detail::type_error*>(&ex));
                case 5:
                    JSON_THROW(*reinterpret_cast<const detail::other_error*>(&ex));
                default:
                    assert(false);
            }
        }
        return false;
    }

    constexpr bool is_errored() const
    {
        return errored;
    }

  private:
    template<typename Value>
    std::pair<bool, BasicJsonType*> handle_value(Value&& v, const bool skip_callback = false)
    {
        assert(not keep_stack.empty());

        if (not keep_stack.back())
        {
            return {false, nullptr};
        }

        auto value = BasicJsonType(std::forward<Value>(v));

        const bool keep = skip_callback or callback(static_cast<int>(ref_stack.size()), parse_event_t::value, value);

        if (not keep)
        {
            return {false, nullptr};
        }

        if (ref_stack.empty())
        {
            root = std::move(value);
            return {true, &root};
        }
        else
        {
            if (not ref_stack.back())
            {
                return {false, nullptr};
            }

            assert(ref_stack.back()->is_array() or ref_stack.back()->is_object());
            if (ref_stack.back()->is_array())
            {
                ref_stack.back()->m_value.array->push_back(std::move(value));
                return {true, &(ref_stack.back()->m_value.array->back())};
            }
            else
            {
                assert(not key_keep_stack.empty());
                const bool store_element = key_keep_stack.back();
                key_keep_stack.pop_back();

                if (not store_element)
                {
                    return {false, nullptr};
                }

                assert(object_element);
                *object_element = std::move(value);
                return {true, object_element};
            }
        }
    }

    BasicJsonType& root;
    std::vector<BasicJsonType*> ref_stack;
    std::vector<bool> keep_stack;
    std::vector<bool> key_keep_stack;
    BasicJsonType* object_element = nullptr;
    bool errored = false;
    const parser_callback_t callback = nullptr;
    const bool allow_exceptions = true;
    BasicJsonType discarded = BasicJsonType::value_t::discarded;
};

template<typename BasicJsonType>
class json_sax_acceptor
{
  public:
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;

    bool null()
    {
        return true;
    }

    bool boolean(bool)
    {
        return true;
    }

    bool number_integer(number_integer_t)
    {
        return true;
    }

    bool number_unsigned(number_unsigned_t)
    {
        return true;
    }

    bool number_float(number_float_t, const string_t&)
    {
        return true;
    }

    bool string(string_t&)
    {
        return true;
    }

    bool start_object(std::size_t = std::size_t(-1))
    {
        return true;
    }

    bool key(string_t&)
    {
        return true;
    }

    bool end_object()
    {
        return true;
    }

    bool start_array(std::size_t = std::size_t(-1))
    {
        return true;
    }

    bool end_array()
    {
        return true;
    }

    bool parse_error(std::size_t, const std::string&, const detail::exception&)
    {
        return false;
    }
};
}

}


namespace nlohmann
{
namespace detail
{
template<typename BasicJsonType>
class parser
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using lexer_t = lexer<BasicJsonType>;
    using token_type = typename lexer_t::token_type;

  public:
    enum class parse_event_t : uint8_t
    {
        object_start,
        object_end,
        array_start,
        array_end,
        key,
        value
    };

    using parser_callback_t =
        std::function<bool(int depth, parse_event_t event, BasicJsonType& parsed)>;

    explicit parser(detail::input_adapter_t&& adapter,
                    const parser_callback_t cb = nullptr,
                    const bool allow_exceptions_ = true)
        : callback(cb), m_lexer(std::move(adapter)), allow_exceptions(allow_exceptions_)
    {
        get_token();
    }

    void parse(const bool strict, BasicJsonType& result)
    {
        if (callback)
        {
            json_sax_dom_callback_parser<BasicJsonType> sdp(result, callback, allow_exceptions);
            sax_parse_internal(&sdp);
            result.assert_invariant();

            if (strict and (get_token() != token_type::end_of_input))
            {
                sdp.parse_error(m_lexer.get_position(),
                                m_lexer.get_token_string(),
                                parse_error::create(101, m_lexer.get_position(), exception_message(token_type::end_of_input)));
            }

            if (sdp.is_errored())
            {
                result = value_t::discarded;
                return;
            }

            if (result.is_discarded())
            {
                result = nullptr;
            }
        }
        else
        {
            json_sax_dom_parser<BasicJsonType> sdp(result, allow_exceptions);
            sax_parse_internal(&sdp);
            result.assert_invariant();

            if (strict and (get_token() != token_type::end_of_input))
            {
                sdp.parse_error(m_lexer.get_position(),
                                m_lexer.get_token_string(),
                                parse_error::create(101, m_lexer.get_position(), exception_message(token_type::end_of_input)));
            }

            if (sdp.is_errored())
            {
                result = value_t::discarded;
                return;
            }
        }
    }

    bool accept(const bool strict = true)
    {
        json_sax_acceptor<BasicJsonType> sax_acceptor;
        return sax_parse(&sax_acceptor, strict);
    }

    template <typename SAX>
    bool sax_parse(SAX* sax, const bool strict = true)
    {
        (void)detail::is_sax_static_asserts<SAX, BasicJsonType> {};
        const bool result = sax_parse_internal(sax);

        if (result and strict and (get_token() != token_type::end_of_input))
        {
            return sax->parse_error(m_lexer.get_position(),
                                    m_lexer.get_token_string(),
                                    parse_error::create(101, m_lexer.get_position(), exception_message(token_type::end_of_input)));
        }

        return result;
    }

  private:
    template <typename SAX>
    bool sax_parse_internal(SAX* sax)
    {
        std::vector<bool> states;
        bool skip_to_state_evaluation = false;

        while (true)
        {
            if (not skip_to_state_evaluation)
            {
                switch (last_token)
                {
                    case token_type::begin_object:
                    {
                        if (JSON_UNLIKELY(not sax->start_object(std::size_t(-1))))
                        {
                            return false;
                        }

                        if (get_token() == token_type::end_object)
                        {
                            if (JSON_UNLIKELY(not sax->end_object()))
                            {
                                return false;
                            }
                            break;
                        }

                        if (JSON_UNLIKELY(last_token != token_type::value_string))
                        {
                            return sax->parse_error(m_lexer.get_position(),
                                                    m_lexer.get_token_string(),
                                                    parse_error::create(101, m_lexer.get_position(), exception_message(token_type::value_string)));
                        }
                        else
                        {
                            if (JSON_UNLIKELY(not sax->key(m_lexer.get_string())))
                            {
                                return false;
                            }
                        }

                        if (JSON_UNLIKELY(get_token() != token_type::name_separator))
                        {
                            return sax->parse_error(m_lexer.get_position(),
                                                    m_lexer.get_token_string(),
                                                    parse_error::create(101, m_lexer.get_position(), exception_message(token_type::name_separator)));
                        }

                        states.push_back(false);

                        get_token();
                        continue;
                    }

                    case token_type::begin_array:
                    {
                        if (JSON_UNLIKELY(not sax->start_array(std::size_t(-1))))
                        {
                            return false;
                        }

                        if (get_token() == token_type::end_array)
                        {
                            if (JSON_UNLIKELY(not sax->end_array()))
                            {
                                return false;
                            }
                            break;
                        }

                        states.push_back(true);

                        continue;
                    }

                    case token_type::value_float:
                    {
                        const auto res = m_lexer.get_number_float();

                        if (JSON_UNLIKELY(not std::isfinite(res)))
                        {
                            return sax->parse_error(m_lexer.get_position(),
                                                    m_lexer.get_token_string(),
                                                    out_of_range::create(406, "number overflow parsing '" + m_lexer.get_token_string() + "'"));
                        }
                        else
                        {
                            if (JSON_UNLIKELY(not sax->number_float(res, m_lexer.get_string())))
                            {
                                return false;
                            }
                            break;
                        }
                    }

                    case token_type::literal_false:
                    {
                        if (JSON_UNLIKELY(not sax->boolean(false)))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::literal_null:
                    {
                        if (JSON_UNLIKELY(not sax->null()))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::literal_true:
                    {
                        if (JSON_UNLIKELY(not sax->boolean(true)))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::value_integer:
                    {
                        if (JSON_UNLIKELY(not sax->number_integer(m_lexer.get_number_integer())))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::value_string:
                    {
                        if (JSON_UNLIKELY(not sax->string(m_lexer.get_string())))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::value_unsigned:
                    {
                        if (JSON_UNLIKELY(not sax->number_unsigned(m_lexer.get_number_unsigned())))
                        {
                            return false;
                        }
                        break;
                    }

                    case token_type::parse_error:
                    {
                        return sax->parse_error(m_lexer.get_position(),
                                                m_lexer.get_token_string(),
                                                parse_error::create(101, m_lexer.get_position(), exception_message(token_type::uninitialized)));
                    }

                    default:      
                    {
                        return sax->parse_error(m_lexer.get_position(),
                                                m_lexer.get_token_string(),
                                                parse_error::create(101, m_lexer.get_position(), exception_message(token_type::literal_or_value)));
                    }
                }
            }
            else
            {
                skip_to_state_evaluation = false;
            }

            if (states.empty())
            {
                return true;
            }
            else
            {
                if (states.back())   
                {
                    if (get_token() == token_type::value_separator)
                    {
                        get_token();
                        continue;
                    }

                    if (JSON_LIKELY(last_token == token_type::end_array))
                    {
                        if (JSON_UNLIKELY(not sax->end_array()))
                        {
                            return false;
                        }

                        assert(not states.empty());
                        states.pop_back();
                        skip_to_state_evaluation = true;
                        continue;
                    }
                    else
                    {
                        return sax->parse_error(m_lexer.get_position(),
                                                m_lexer.get_token_string(),
                                                parse_error::create(101, m_lexer.get_position(), exception_message(token_type::end_array)));
                    }
                }
                else   
                {
                    if (get_token() == token_type::value_separator)
                    {
                        if (JSON_UNLIKELY(get_token() != token_type::value_string))
                        {
                            return sax->parse_error(m_lexer.get_position(),
                                                    m_lexer.get_token_string(),
                                                    parse_error::create(101, m_lexer.get_position(), exception_message(token_type::value_string)));
                        }
                        else
                        {
                            if (JSON_UNLIKELY(not sax->key(m_lexer.get_string())))
                            {
                                return false;
                            }
                        }

                        if (JSON_UNLIKELY(get_token() != token_type::name_separator))
                        {
                            return sax->parse_error(m_lexer.get_position(),
                                                    m_lexer.get_token_string(),
                                                    parse_error::create(101, m_lexer.get_position(), exception_message(token_type::name_separator)));
                        }

                        get_token();
                        continue;
                    }

                    if (JSON_LIKELY(last_token == token_type::end_object))
                    {
                        if (JSON_UNLIKELY(not sax->end_object()))
                        {
                            return false;
                        }

                        assert(not states.empty());
                        states.pop_back();
                        skip_to_state_evaluation = true;
                        continue;
                    }
                    else
                    {
                        return sax->parse_error(m_lexer.get_position(),
                                                m_lexer.get_token_string(),
                                                parse_error::create(101, m_lexer.get_position(), exception_message(token_type::end_object)));
                    }
                }
            }
        }
    }

    token_type get_token()
    {
        return (last_token = m_lexer.scan());
    }

    std::string exception_message(const token_type expected)
    {
        std::string error_msg = "syntax error - ";
        if (last_token == token_type::parse_error)
        {
            error_msg += std::string(m_lexer.get_error_message()) + "; last read: '" +
                         m_lexer.get_token_string() + "'";
        }
        else
        {
            error_msg += "unexpected " + std::string(lexer_t::token_type_name(last_token));
        }

        if (expected != token_type::uninitialized)
        {
            error_msg += "; expected " + std::string(lexer_t::token_type_name(expected));
        }

        return error_msg;
    }

  private:
    const parser_callback_t callback = nullptr;
    token_type last_token = token_type::uninitialized;
    lexer_t m_lexer;
    const bool allow_exceptions = true;
};
}
}


#include <cstddef>  
#include <limits>   

namespace nlohmann
{
namespace detail
{
class primitive_iterator_t
{
  private:
    using difference_type = std::ptrdiff_t;
    static constexpr difference_type begin_value = 0;
    static constexpr difference_type end_value = begin_value + 1;

    difference_type m_it = (std::numeric_limits<std::ptrdiff_t>::min)();

  public:
    constexpr difference_type get_value() const noexcept
    {
        return m_it;
    }

    void set_begin() noexcept
    {
        m_it = begin_value;
    }

    void set_end() noexcept
    {
        m_it = end_value;
    }

    constexpr bool is_begin() const noexcept
    {
        return m_it == begin_value;
    }

    constexpr bool is_end() const noexcept
    {
        return m_it == end_value;
    }

    friend constexpr bool operator==(primitive_iterator_t lhs, primitive_iterator_t rhs) noexcept
    {
        return lhs.m_it == rhs.m_it;
    }

    friend constexpr bool operator<(primitive_iterator_t lhs, primitive_iterator_t rhs) noexcept
    {
        return lhs.m_it < rhs.m_it;
    }

    primitive_iterator_t operator+(difference_type n) noexcept
    {
        auto result = *this;
        result += n;
        return result;
    }

    friend constexpr difference_type operator-(primitive_iterator_t lhs, primitive_iterator_t rhs) noexcept
    {
        return lhs.m_it - rhs.m_it;
    }

    primitive_iterator_t& operator++() noexcept
    {
        ++m_it;
        return *this;
    }

    primitive_iterator_t const operator++(int) noexcept
    {
        auto result = *this;
        ++m_it;
        return result;
    }

    primitive_iterator_t& operator--() noexcept
    {
        --m_it;
        return *this;
    }

    primitive_iterator_t const operator--(int) noexcept
    {
        auto result = *this;
        --m_it;
        return result;
    }

    primitive_iterator_t& operator+=(difference_type n) noexcept
    {
        m_it += n;
        return *this;
    }

    primitive_iterator_t& operator-=(difference_type n) noexcept
    {
        m_it -= n;
        return *this;
    }
};
}
}



namespace nlohmann
{
namespace detail
{
template<typename BasicJsonType> struct internal_iterator
{
    typename BasicJsonType::object_t::iterator object_iterator {};
    typename BasicJsonType::array_t::iterator array_iterator {};
    primitive_iterator_t primitive_iterator {};
};
}
}


#include <ciso646>  
#include <iterator>      
#include <type_traits>    


namespace nlohmann
{
namespace detail
{
template<typename IteratorType> class iteration_proxy;

template<typename BasicJsonType>
class iter_impl
{
    friend iter_impl<typename std::conditional<std::is_const<BasicJsonType>::value, typename std::remove_const<BasicJsonType>::type, const BasicJsonType>::type>;
    friend BasicJsonType;
    friend iteration_proxy<iter_impl>;

    using object_t = typename BasicJsonType::object_t;
    using array_t = typename BasicJsonType::array_t;
    static_assert(is_basic_json<typename std::remove_const<BasicJsonType>::type>::value,
                  "iter_impl only accepts (const) basic_json");

  public:

    using iterator_category = std::bidirectional_iterator_tag;

    using value_type = typename BasicJsonType::value_type;
    using difference_type = typename BasicJsonType::difference_type;
    using pointer = typename std::conditional<std::is_const<BasicJsonType>::value,
          typename BasicJsonType::const_pointer,
          typename BasicJsonType::pointer>::type;
    using reference =
        typename std::conditional<std::is_const<BasicJsonType>::value,
        typename BasicJsonType::const_reference,
        typename BasicJsonType::reference>::type;

    iter_impl() = default;

    explicit iter_impl(pointer object) noexcept : m_object(object)
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
            {
                m_it.object_iterator = typename object_t::iterator();
                break;
            }

            case value_t::array:
            {
                m_it.array_iterator = typename array_t::iterator();
                break;
            }

            default:
            {
                m_it.primitive_iterator = primitive_iterator_t();
                break;
            }
        }
    }

    iter_impl(const iter_impl<typename std::remove_const<BasicJsonType>::type>& other) noexcept
        : m_object(other.m_object), m_it(other.m_it) {}

    iter_impl& operator=(const iter_impl<typename std::remove_const<BasicJsonType>::type>& other) noexcept
    {
        m_object = other.m_object;
        m_it = other.m_it;
        return *this;
    }

  private:
    void set_begin() noexcept
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
            {
                m_it.object_iterator = m_object->m_value.object->begin();
                break;
            }

            case value_t::array:
            {
                m_it.array_iterator = m_object->m_value.array->begin();
                break;
            }

            case value_t::null:
            {
                m_it.primitive_iterator.set_end();
                break;
            }

            default:
            {
                m_it.primitive_iterator.set_begin();
                break;
            }
        }
    }

    void set_end() noexcept
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
            {
                m_it.object_iterator = m_object->m_value.object->end();
                break;
            }

            case value_t::array:
            {
                m_it.array_iterator = m_object->m_value.array->end();
                break;
            }

            default:
            {
                m_it.primitive_iterator.set_end();
                break;
            }
        }
    }

  public:
    reference operator*() const
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
            {
                assert(m_it.object_iterator != m_object->m_value.object->end());
                return m_it.object_iterator->second;
            }

            case value_t::array:
            {
                assert(m_it.array_iterator != m_object->m_value.array->end());
                return *m_it.array_iterator;
            }

            case value_t::null:
                JSON_THROW(invalid_iterator::create(214, "cannot get value"));

            default:
            {
                if (JSON_LIKELY(m_it.primitive_iterator.is_begin()))
                {
                    return *m_object;
                }

                JSON_THROW(invalid_iterator::create(214, "cannot get value"));
            }
        }
    }

    pointer operator->() const
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
            {
                assert(m_it.object_iterator != m_object->m_value.object->end());
                return &(m_it.object_iterator->second);
            }

            case value_t::array:
            {
                assert(m_it.array_iterator != m_object->m_value.array->end());
                return &*m_it.array_iterator;
            }

            default:
            {
                if (JSON_LIKELY(m_it.primitive_iterator.is_begin()))
                {
                    return m_object;
                }

                JSON_THROW(invalid_iterator::create(214, "cannot get value"));
            }
        }
    }

    iter_impl const operator++(int)
    {
        auto result = *this;
        ++(*this);
        return result;
    }

    iter_impl& operator++()
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
            {
                std::advance(m_it.object_iterator, 1);
                break;
            }

            case value_t::array:
            {
                std::advance(m_it.array_iterator, 1);
                break;
            }

            default:
            {
                ++m_it.primitive_iterator;
                break;
            }
        }

        return *this;
    }

    iter_impl const operator--(int)
    {
        auto result = *this;
        --(*this);
        return result;
    }

    iter_impl& operator--()
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
            {
                std::advance(m_it.object_iterator, -1);
                break;
            }

            case value_t::array:
            {
                std::advance(m_it.array_iterator, -1);
                break;
            }

            default:
            {
                --m_it.primitive_iterator;
                break;
            }
        }

        return *this;
    }

    bool operator==(const iter_impl& other) const
    {
        if (JSON_UNLIKELY(m_object != other.m_object))
        {
            JSON_THROW(invalid_iterator::create(212, "cannot compare iterators of different containers"));
        }

        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
                return (m_it.object_iterator == other.m_it.object_iterator);

            case value_t::array:
                return (m_it.array_iterator == other.m_it.array_iterator);

            default:
                return (m_it.primitive_iterator == other.m_it.primitive_iterator);
        }
    }

    bool operator!=(const iter_impl& other) const
    {
        return not operator==(other);
    }

    bool operator<(const iter_impl& other) const
    {
        if (JSON_UNLIKELY(m_object != other.m_object))
        {
            JSON_THROW(invalid_iterator::create(212, "cannot compare iterators of different containers"));
        }

        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
                JSON_THROW(invalid_iterator::create(213, "cannot compare order of object iterators"));

            case value_t::array:
                return (m_it.array_iterator < other.m_it.array_iterator);

            default:
                return (m_it.primitive_iterator < other.m_it.primitive_iterator);
        }
    }

    bool operator<=(const iter_impl& other) const
    {
        return not other.operator < (*this);
    }

    bool operator>(const iter_impl& other) const
    {
        return not operator<=(other);
    }

    bool operator>=(const iter_impl& other) const
    {
        return not operator<(other);
    }

    iter_impl& operator+=(difference_type i)
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
                JSON_THROW(invalid_iterator::create(209, "cannot use offsets with object iterators"));

            case value_t::array:
            {
                std::advance(m_it.array_iterator, i);
                break;
            }

            default:
            {
                m_it.primitive_iterator += i;
                break;
            }
        }

        return *this;
    }

    iter_impl& operator-=(difference_type i)
    {
        return operator+=(-i);
    }

    iter_impl operator+(difference_type i) const
    {
        auto result = *this;
        result += i;
        return result;
    }

    friend iter_impl operator+(difference_type i, const iter_impl& it)
    {
        auto result = it;
        result += i;
        return result;
    }

    iter_impl operator-(difference_type i) const
    {
        auto result = *this;
        result -= i;
        return result;
    }

    difference_type operator-(const iter_impl& other) const
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
                JSON_THROW(invalid_iterator::create(209, "cannot use offsets with object iterators"));

            case value_t::array:
                return m_it.array_iterator - other.m_it.array_iterator;

            default:
                return m_it.primitive_iterator - other.m_it.primitive_iterator;
        }
    }

    reference operator[](difference_type n) const
    {
        assert(m_object != nullptr);

        switch (m_object->m_type)
        {
            case value_t::object:
                JSON_THROW(invalid_iterator::create(208, "cannot use operator[] for object iterators"));

            case value_t::array:
                return *std::next(m_it.array_iterator, n);

            case value_t::null:
                JSON_THROW(invalid_iterator::create(214, "cannot get value"));

            default:
            {
                if (JSON_LIKELY(m_it.primitive_iterator.get_value() == -n))
                {
                    return *m_object;
                }

                JSON_THROW(invalid_iterator::create(214, "cannot get value"));
            }
        }
    }

    const typename object_t::key_type& key() const
    {
        assert(m_object != nullptr);

        if (JSON_LIKELY(m_object->is_object()))
        {
            return m_it.object_iterator->first;
        }

        JSON_THROW(invalid_iterator::create(207, "cannot use key() for non-object iterators"));
    }

    reference value() const
    {
        return operator*();
    }

  private:
    pointer m_object = nullptr;
    internal_iterator<typename std::remove_const<BasicJsonType>::type> m_it;
};
}
}


#include <cstddef>  
#include <iterator>  
#include <utility>  

namespace nlohmann
{
namespace detail
{
template<typename Base>
class json_reverse_iterator : public std::reverse_iterator<Base>
{
  public:
    using difference_type = std::ptrdiff_t;
    using base_iterator = std::reverse_iterator<Base>;
    using reference = typename Base::reference;

    explicit json_reverse_iterator(const typename base_iterator::iterator_type& it) noexcept
        : base_iterator(it) {}

    explicit json_reverse_iterator(const base_iterator& it) noexcept : base_iterator(it) {}

    json_reverse_iterator const operator++(int)
    {
        return static_cast<json_reverse_iterator>(base_iterator::operator++(1));
    }

    json_reverse_iterator& operator++()
    {
        return static_cast<json_reverse_iterator&>(base_iterator::operator++());
    }

    json_reverse_iterator const operator--(int)
    {
        return static_cast<json_reverse_iterator>(base_iterator::operator--(1));
    }

    json_reverse_iterator& operator--()
    {
        return static_cast<json_reverse_iterator&>(base_iterator::operator--());
    }

    json_reverse_iterator& operator+=(difference_type i)
    {
        return static_cast<json_reverse_iterator&>(base_iterator::operator+=(i));
    }

    json_reverse_iterator operator+(difference_type i) const
    {
        return static_cast<json_reverse_iterator>(base_iterator::operator+(i));
    }

    json_reverse_iterator operator-(difference_type i) const
    {
        return static_cast<json_reverse_iterator>(base_iterator::operator-(i));
    }

    difference_type operator-(const json_reverse_iterator& other) const
    {
        return base_iterator(*this) - base_iterator(other);
    }

    reference operator[](difference_type n) const
    {
        return *(this->operator+(n));
    }

    auto key() const -> decltype(std::declval<Base>().key())
    {
        auto it = --this->base();
        return it.key();
    }

    reference value() const
    {
        auto it = --this->base();
        return it.operator * ();
    }
};
}
}


#include <algorithm>  
#include <cstddef>  
#include <ios>  
#include <iterator>  
#include <memory>   
#include <ostream>  
#include <string>  
#include <vector>  

namespace nlohmann
{
namespace detail
{
template<typename CharType> struct output_adapter_protocol
{
    virtual void write_character(CharType c) = 0;
    virtual void write_characters(const CharType* s, std::size_t length) = 0;
    virtual ~output_adapter_protocol() = default;
};

template<typename CharType>
using output_adapter_t = std::shared_ptr<output_adapter_protocol<CharType>>;

template<typename CharType>
class output_vector_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_vector_adapter(std::vector<CharType>& vec) : v(vec) {}

    void write_character(CharType c) override
    {
        v.push_back(c);
    }

    void write_characters(const CharType* s, std::size_t length) override
    {
        std::copy(s, s + length, std::back_inserter(v));
    }

  private:
    std::vector<CharType>& v;
};

template<typename CharType>
class output_stream_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_stream_adapter(std::basic_ostream<CharType>& s) : stream(s) {}

    void write_character(CharType c) override
    {
        stream.put(c);
    }

    void write_characters(const CharType* s, std::size_t length) override
    {
        stream.write(s, static_cast<std::streamsize>(length));
    }

  private:
    std::basic_ostream<CharType>& stream;
};

template<typename CharType, typename StringType = std::basic_string<CharType>>
class output_string_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_string_adapter(StringType& s) : str(s) {}

    void write_character(CharType c) override
    {
        str.push_back(c);
    }

    void write_characters(const CharType* s, std::size_t length) override
    {
        str.append(s, length);
    }

  private:
    StringType& str;
};

template<typename CharType, typename StringType = std::basic_string<CharType>>
class output_adapter
{
  public:
    output_adapter(std::vector<CharType>& vec)
        : oa(std::make_shared<output_vector_adapter<CharType>>(vec)) {}

    output_adapter(std::basic_ostream<CharType>& s)
        : oa(std::make_shared<output_stream_adapter<CharType>>(s)) {}

    output_adapter(StringType& s)
        : oa(std::make_shared<output_string_adapter<CharType, StringType>>(s)) {}

    operator output_adapter_t<CharType>()
    {
        return oa;
    }

  private:
    output_adapter_t<CharType> oa = nullptr;
};
}
}


#include <algorithm>  
#include <array>  
#include <cassert>  
#include <cmath>  
#include <cstddef>  
#include <cstdint>     
#include <cstdio>  
#include <cstring>  
#include <iterator>  
#include <limits>  
#include <string>   
#include <utility>   


namespace nlohmann
{
namespace detail
{
template<typename BasicJsonType, typename SAX = json_sax_dom_parser<BasicJsonType>>
class binary_reader
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using json_sax_t = SAX;

  public:
    explicit binary_reader(input_adapter_t adapter) : ia(std::move(adapter))
    {
        (void)detail::is_sax_static_asserts<SAX, BasicJsonType> {};
        assert(ia);
    }

    bool sax_parse(const input_format_t format,
                   json_sax_t* sax_,
                   const bool strict = true)
    {
        sax = sax_;
        bool result = false;

        switch (format)
        {
            case input_format_t::cbor:
                result = parse_cbor_internal();
                break;

            case input_format_t::msgpack:
                result = parse_msgpack_internal();
                break;

            case input_format_t::ubjson:
                result = parse_ubjson_internal();
                break;

            default:
                assert(false);
        }

        if (result and strict)
        {
            if (format == input_format_t::ubjson)
            {
                get_ignore_noop();
            }
            else
            {
                get();
            }

            if (JSON_UNLIKELY(current != std::char_traits<char>::eof()))
            {
                return sax->parse_error(chars_read, get_token_string(), parse_error::create(110, chars_read, "expected end of input"));
            }
        }

        return result;
    }

    static constexpr bool little_endianess(int num = 1) noexcept
    {
        return (*reinterpret_cast<char*>(&num) == 1);
    }

  private:
    bool parse_cbor_internal(const bool get_char = true)
    {
        switch (get_char ? get() : current)
        {
            case std::char_traits<char>::eof():
                return unexpect_eof();

            case 0x00:
            case 0x01:
            case 0x02:
            case 0x03:
            case 0x04:
            case 0x05:
            case 0x06:
            case 0x07:
            case 0x08:
            case 0x09:
            case 0x0A:
            case 0x0B:
            case 0x0C:
            case 0x0D:
            case 0x0E:
            case 0x0F:
            case 0x10:
            case 0x11:
            case 0x12:
            case 0x13:
            case 0x14:
            case 0x15:
            case 0x16:
            case 0x17:
                return sax->number_unsigned(static_cast<number_unsigned_t>(current));

            case 0x18:      
            {
                uint8_t number;
                return get_number(number) and sax->number_unsigned(number);
            }

            case 0x19:      
            {
                uint16_t number;
                return get_number(number) and sax->number_unsigned(number);
            }

            case 0x1A:      
            {
                uint32_t number;
                return get_number(number) and sax->number_unsigned(number);
            }

            case 0x1B:      
            {
                uint64_t number;
                return get_number(number) and sax->number_unsigned(number);
            }

            case 0x20:
            case 0x21:
            case 0x22:
            case 0x23:
            case 0x24:
            case 0x25:
            case 0x26:
            case 0x27:
            case 0x28:
            case 0x29:
            case 0x2A:
            case 0x2B:
            case 0x2C:
            case 0x2D:
            case 0x2E:
            case 0x2F:
            case 0x30:
            case 0x31:
            case 0x32:
            case 0x33:
            case 0x34:
            case 0x35:
            case 0x36:
            case 0x37:
                return sax->number_integer(static_cast<int8_t>(0x20 - 1 - current));

            case 0x38:      
            {
                uint8_t number;
                return get_number(number) and sax->number_integer(static_cast<number_integer_t>(-1) - number);
            }

            case 0x39:       
            {
                uint16_t number;
                return get_number(number) and sax->number_integer(static_cast<number_integer_t>(-1) - number);
            }

            case 0x3A:       
            {
                uint32_t number;
                return get_number(number) and sax->number_integer(static_cast<number_integer_t>(-1) - number);
            }

            case 0x3B:       
            {
                uint64_t number;
                return get_number(number) and sax->number_integer(static_cast<number_integer_t>(-1)
                        - static_cast<number_integer_t>(number));
            }

            case 0x60:
            case 0x61:
            case 0x62:
            case 0x63:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
            case 0x68:
            case 0x69:
            case 0x6A:
            case 0x6B:
            case 0x6C:
            case 0x6D:
            case 0x6E:
            case 0x6F:
            case 0x70:
            case 0x71:
            case 0x72:
            case 0x73:
            case 0x74:
            case 0x75:
            case 0x76:
            case 0x77:
            case 0x78:        
            case 0x79:        
            case 0x7A:        
            case 0x7B:        
            case 0x7F:     
            {
                string_t s;
                return get_cbor_string(s) and sax->string(s);
            }

            case 0x80:
            case 0x81:
            case 0x82:
            case 0x83:
            case 0x84:
            case 0x85:
            case 0x86:
            case 0x87:
            case 0x88:
            case 0x89:
            case 0x8A:
            case 0x8B:
            case 0x8C:
            case 0x8D:
            case 0x8E:
            case 0x8F:
            case 0x90:
            case 0x91:
            case 0x92:
            case 0x93:
            case 0x94:
            case 0x95:
            case 0x96:
            case 0x97:
                return get_cbor_array(static_cast<std::size_t>(current & 0x1F));

            case 0x98:       
            {
                uint8_t len;
                return get_number(len) and get_cbor_array(static_cast<std::size_t>(len));
            }

            case 0x99:       
            {
                uint16_t len;
                return get_number(len) and get_cbor_array(static_cast<std::size_t>(len));
            }

            case 0x9A:       
            {
                uint32_t len;
                return get_number(len) and get_cbor_array(static_cast<std::size_t>(len));
            }

            case 0x9B:       
            {
                uint64_t len;
                return get_number(len) and get_cbor_array(static_cast<std::size_t>(len));
            }

            case 0x9F:    
                return get_cbor_array(std::size_t(-1));

            case 0xA0:
            case 0xA1:
            case 0xA2:
            case 0xA3:
            case 0xA4:
            case 0xA5:
            case 0xA6:
            case 0xA7:
            case 0xA8:
            case 0xA9:
            case 0xAA:
            case 0xAB:
            case 0xAC:
            case 0xAD:
            case 0xAE:
            case 0xAF:
            case 0xB0:
            case 0xB1:
            case 0xB2:
            case 0xB3:
            case 0xB4:
            case 0xB5:
            case 0xB6:
            case 0xB7:
                return get_cbor_object(static_cast<std::size_t>(current & 0x1F));

            case 0xB8:       
            {
                uint8_t len;
                return get_number(len) and get_cbor_object(static_cast<std::size_t>(len));
            }

            case 0xB9:       
            {
                uint16_t len;
                return get_number(len) and get_cbor_object(static_cast<std::size_t>(len));
            }

            case 0xBA:       
            {
                uint32_t len;
                return get_number(len) and get_cbor_object(static_cast<std::size_t>(len));
            }

            case 0xBB:       
            {
                uint64_t len;
                return get_number(len) and get_cbor_object(static_cast<std::size_t>(len));
            }

            case 0xBF:    
                return get_cbor_object(std::size_t(-1));

            case 0xF4:  
                return sax->boolean(false);

            case 0xF5:  
                return sax->boolean(true);

            case 0xF6:  
                return sax->null();

            case 0xF9:      
            {
                const int byte1 = get();
                if (JSON_UNLIKELY(not unexpect_eof()))
                {
                    return false;
                }
                const int byte2 = get();
                if (JSON_UNLIKELY(not unexpect_eof()))
                {
                    return false;
                }

                const int half = (byte1 << 8) + byte2;
                const double val = [&half]
                {
                    const int exp = (half >> 10) & 0x1F;
                    const int mant = half & 0x3FF;
                    assert(0 <= exp and exp <= 32);
                    assert(0 <= mant and mant <= 1024);
                    switch (exp)
                    {
                        case 0:
                            return std::ldexp(mant, -24);
                        case 31:
                            return (mant == 0)
                            ? std::numeric_limits<double>::infinity()
                            : std::numeric_limits<double>::quiet_NaN();
                        default:
                            return std::ldexp(mant + 1024, exp - 25);
                    }
                }();
                return sax->number_float((half & 0x8000) != 0
                                         ? static_cast<number_float_t>(-val)
                                         : static_cast<number_float_t>(val), "");
            }

            case 0xFA:      
            {
                float number;
                return get_number(number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0xFB:      
            {
                double number;
                return get_number(number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            default:          
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, "error reading CBOR; last byte: 0x" + last_token));
            }
        }
    }

    bool parse_msgpack_internal()
    {
        switch (get())
        {
            case std::char_traits<char>::eof():
                return unexpect_eof();

            case 0x00:
            case 0x01:
            case 0x02:
            case 0x03:
            case 0x04:
            case 0x05:
            case 0x06:
            case 0x07:
            case 0x08:
            case 0x09:
            case 0x0A:
            case 0x0B:
            case 0x0C:
            case 0x0D:
            case 0x0E:
            case 0x0F:
            case 0x10:
            case 0x11:
            case 0x12:
            case 0x13:
            case 0x14:
            case 0x15:
            case 0x16:
            case 0x17:
            case 0x18:
            case 0x19:
            case 0x1A:
            case 0x1B:
            case 0x1C:
            case 0x1D:
            case 0x1E:
            case 0x1F:
            case 0x20:
            case 0x21:
            case 0x22:
            case 0x23:
            case 0x24:
            case 0x25:
            case 0x26:
            case 0x27:
            case 0x28:
            case 0x29:
            case 0x2A:
            case 0x2B:
            case 0x2C:
            case 0x2D:
            case 0x2E:
            case 0x2F:
            case 0x30:
            case 0x31:
            case 0x32:
            case 0x33:
            case 0x34:
            case 0x35:
            case 0x36:
            case 0x37:
            case 0x38:
            case 0x39:
            case 0x3A:
            case 0x3B:
            case 0x3C:
            case 0x3D:
            case 0x3E:
            case 0x3F:
            case 0x40:
            case 0x41:
            case 0x42:
            case 0x43:
            case 0x44:
            case 0x45:
            case 0x46:
            case 0x47:
            case 0x48:
            case 0x49:
            case 0x4A:
            case 0x4B:
            case 0x4C:
            case 0x4D:
            case 0x4E:
            case 0x4F:
            case 0x50:
            case 0x51:
            case 0x52:
            case 0x53:
            case 0x54:
            case 0x55:
            case 0x56:
            case 0x57:
            case 0x58:
            case 0x59:
            case 0x5A:
            case 0x5B:
            case 0x5C:
            case 0x5D:
            case 0x5E:
            case 0x5F:
            case 0x60:
            case 0x61:
            case 0x62:
            case 0x63:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
            case 0x68:
            case 0x69:
            case 0x6A:
            case 0x6B:
            case 0x6C:
            case 0x6D:
            case 0x6E:
            case 0x6F:
            case 0x70:
            case 0x71:
            case 0x72:
            case 0x73:
            case 0x74:
            case 0x75:
            case 0x76:
            case 0x77:
            case 0x78:
            case 0x79:
            case 0x7A:
            case 0x7B:
            case 0x7C:
            case 0x7D:
            case 0x7E:
            case 0x7F:
                return sax->number_unsigned(static_cast<number_unsigned_t>(current));

            case 0x80:
            case 0x81:
            case 0x82:
            case 0x83:
            case 0x84:
            case 0x85:
            case 0x86:
            case 0x87:
            case 0x88:
            case 0x89:
            case 0x8A:
            case 0x8B:
            case 0x8C:
            case 0x8D:
            case 0x8E:
            case 0x8F:
                return get_msgpack_object(static_cast<std::size_t>(current & 0x0F));

            case 0x90:
            case 0x91:
            case 0x92:
            case 0x93:
            case 0x94:
            case 0x95:
            case 0x96:
            case 0x97:
            case 0x98:
            case 0x99:
            case 0x9A:
            case 0x9B:
            case 0x9C:
            case 0x9D:
            case 0x9E:
            case 0x9F:
                return get_msgpack_array(static_cast<std::size_t>(current & 0x0F));

            case 0xA0:
            case 0xA1:
            case 0xA2:
            case 0xA3:
            case 0xA4:
            case 0xA5:
            case 0xA6:
            case 0xA7:
            case 0xA8:
            case 0xA9:
            case 0xAA:
            case 0xAB:
            case 0xAC:
            case 0xAD:
            case 0xAE:
            case 0xAF:
            case 0xB0:
            case 0xB1:
            case 0xB2:
            case 0xB3:
            case 0xB4:
            case 0xB5:
            case 0xB6:
            case 0xB7:
            case 0xB8:
            case 0xB9:
            case 0xBA:
            case 0xBB:
            case 0xBC:
            case 0xBD:
            case 0xBE:
            case 0xBF:
            {
                string_t s;
                return get_msgpack_string(s) and sax->string(s);
            }

            case 0xC0:  
                return sax->null();

            case 0xC2:  
                return sax->boolean(false);

            case 0xC3:  
                return sax->boolean(true);

            case 0xCA:   
            {
                float number;
                return get_number(number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0xCB:   
            {
                double number;
                return get_number(number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 0xCC:   
            {
                uint8_t number;
                return get_number(number) and sax->number_unsigned(number);
            }

            case 0xCD:   
            {
                uint16_t number;
                return get_number(number) and sax->number_unsigned(number);
            }

            case 0xCE:   
            {
                uint32_t number;
                return get_number(number) and sax->number_unsigned(number);
            }

            case 0xCF:   
            {
                uint64_t number;
                return get_number(number) and sax->number_unsigned(number);
            }

            case 0xD0:   
            {
                int8_t number;
                return get_number(number) and sax->number_integer(number);
            }

            case 0xD1:   
            {
                int16_t number;
                return get_number(number) and sax->number_integer(number);
            }

            case 0xD2:   
            {
                int32_t number;
                return get_number(number) and sax->number_integer(number);
            }

            case 0xD3:   
            {
                int64_t number;
                return get_number(number) and sax->number_integer(number);
            }

            case 0xD9:   
            case 0xDA:   
            case 0xDB:   
            {
                string_t s;
                return get_msgpack_string(s) and sax->string(s);
            }

            case 0xDC:   
            {
                uint16_t len;
                return get_number(len) and get_msgpack_array(static_cast<std::size_t>(len));
            }

            case 0xDD:   
            {
                uint32_t len;
                return get_number(len) and get_msgpack_array(static_cast<std::size_t>(len));
            }

            case 0xDE:   
            {
                uint16_t len;
                return get_number(len) and get_msgpack_object(static_cast<std::size_t>(len));
            }

            case 0xDF:   
            {
                uint32_t len;
                return get_number(len) and get_msgpack_object(static_cast<std::size_t>(len));
            }

            case 0xE0:
            case 0xE1:
            case 0xE2:
            case 0xE3:
            case 0xE4:
            case 0xE5:
            case 0xE6:
            case 0xE7:
            case 0xE8:
            case 0xE9:
            case 0xEA:
            case 0xEB:
            case 0xEC:
            case 0xED:
            case 0xEE:
            case 0xEF:
            case 0xF0:
            case 0xF1:
            case 0xF2:
            case 0xF3:
            case 0xF4:
            case 0xF5:
            case 0xF6:
            case 0xF7:
            case 0xF8:
            case 0xF9:
            case 0xFA:
            case 0xFB:
            case 0xFC:
            case 0xFD:
            case 0xFE:
            case 0xFF:
                return sax->number_integer(static_cast<int8_t>(current));

            default:   
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, "error reading MessagePack; last byte: 0x" + last_token));
            }
        }
    }

    bool parse_ubjson_internal(const bool get_char = true)
    {
        return get_ubjson_value(get_char ? get_ignore_noop() : current);
    }

    int get()
    {
        ++chars_read;
        return (current = ia->get_character());
    }

    int get_ignore_noop()
    {
        do
        {
            get();
        }
        while (current == 'N');

        return current;
    }

    template<typename NumberType>
    bool get_number(NumberType& result)
    {
        std::array<uint8_t, sizeof(NumberType)> vec;
        for (std::size_t i = 0; i < sizeof(NumberType); ++i)
        {
            get();
            if (JSON_UNLIKELY(not unexpect_eof()))
            {
                return false;
            }

            if (is_little_endian)
            {
                vec[sizeof(NumberType) - i - 1] = static_cast<uint8_t>(current);
            }
            else
            {
                vec[i] = static_cast<uint8_t>(current);  
            }
        }

        std::memcpy(&result, vec.data(), sizeof(NumberType));
        return true;
    }

    template<typename NumberType>
    bool get_string(const NumberType len, string_t& result)
    {
        bool success = true;
        std::generate_n(std::back_inserter(result), len, [this, &success]()
        {
            get();
            if (JSON_UNLIKELY(not unexpect_eof()))
            {
                success = false;
            }
            return static_cast<char>(current);
        });
        return success;
    }

    bool get_cbor_string(string_t& result)
    {
        if (JSON_UNLIKELY(not unexpect_eof()))
        {
            return false;
        }

        switch (current)
        {
            case 0x60:
            case 0x61:
            case 0x62:
            case 0x63:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
            case 0x68:
            case 0x69:
            case 0x6A:
            case 0x6B:
            case 0x6C:
            case 0x6D:
            case 0x6E:
            case 0x6F:
            case 0x70:
            case 0x71:
            case 0x72:
            case 0x73:
            case 0x74:
            case 0x75:
            case 0x76:
            case 0x77:
            {
                return get_string(current & 0x1F, result);
            }

            case 0x78:        
            {
                uint8_t len;
                return get_number(len) and get_string(len, result);
            }

            case 0x79:        
            {
                uint16_t len;
                return get_number(len) and get_string(len, result);
            }

            case 0x7A:        
            {
                uint32_t len;
                return get_number(len) and get_string(len, result);
            }

            case 0x7B:        
            {
                uint64_t len;
                return get_number(len) and get_string(len, result);
            }

            case 0x7F:     
            {
                while (get() != 0xFF)
                {
                    string_t chunk;
                    if (not get_cbor_string(chunk))
                    {
                        return false;
                    }
                    result.append(chunk);
                }
                return true;
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, "expected a CBOR string; last byte: 0x" + last_token));
            }
        }
    }

    bool get_cbor_array(const std::size_t len)
    {
        if (JSON_UNLIKELY(not sax->start_array(len)))
        {
            return false;
        }

        if (len != std::size_t(-1))
            for (std::size_t i = 0; i < len; ++i)
            {
                if (JSON_UNLIKELY(not parse_cbor_internal()))
                {
                    return false;
                }
            }
        else
        {
            while (get() != 0xFF)
            {
                if (JSON_UNLIKELY(not parse_cbor_internal(false)))
                {
                    return false;
                }
            }
        }

        return sax->end_array();
    }

    bool get_cbor_object(const std::size_t len)
    {
        if (not JSON_UNLIKELY(sax->start_object(len)))
        {
            return false;
        }

        string_t key;
        if (len != std::size_t(-1))
        {
            for (std::size_t i = 0; i < len; ++i)
            {
                get();
                if (JSON_UNLIKELY(not get_cbor_string(key) or not sax->key(key)))
                {
                    return false;
                }

                if (JSON_UNLIKELY(not parse_cbor_internal()))
                {
                    return false;
                }
                key.clear();
            }
        }
        else
        {
            while (get() != 0xFF)
            {
                if (JSON_UNLIKELY(not get_cbor_string(key) or not sax->key(key)))
                {
                    return false;
                }

                if (JSON_UNLIKELY(not parse_cbor_internal()))
                {
                    return false;
                }
                key.clear();
            }
        }

        return sax->end_object();
    }

    bool get_msgpack_string(string_t& result)
    {
        if (JSON_UNLIKELY(not unexpect_eof()))
        {
            return false;
        }

        switch (current)
        {
            case 0xA0:
            case 0xA1:
            case 0xA2:
            case 0xA3:
            case 0xA4:
            case 0xA5:
            case 0xA6:
            case 0xA7:
            case 0xA8:
            case 0xA9:
            case 0xAA:
            case 0xAB:
            case 0xAC:
            case 0xAD:
            case 0xAE:
            case 0xAF:
            case 0xB0:
            case 0xB1:
            case 0xB2:
            case 0xB3:
            case 0xB4:
            case 0xB5:
            case 0xB6:
            case 0xB7:
            case 0xB8:
            case 0xB9:
            case 0xBA:
            case 0xBB:
            case 0xBC:
            case 0xBD:
            case 0xBE:
            case 0xBF:
            {
                return get_string(current & 0x1F, result);
            }

            case 0xD9:   
            {
                uint8_t len;
                return get_number(len) and get_string(len, result);
            }

            case 0xDA:   
            {
                uint16_t len;
                return get_number(len) and get_string(len, result);
            }

            case 0xDB:   
            {
                uint32_t len;
                return get_number(len) and get_string(len, result);
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, "expected a MessagePack string; last byte: 0x" + last_token));
            }
        }
    }

    bool get_msgpack_array(const std::size_t len)
    {
        if (JSON_UNLIKELY(not sax->start_array(len)))
        {
            return false;
        }

        for (std::size_t i = 0; i < len; ++i)
        {
            if (JSON_UNLIKELY(not parse_msgpack_internal()))
            {
                return false;
            }
        }

        return sax->end_array();
    }

    bool get_msgpack_object(const std::size_t len)
    {
        if (JSON_UNLIKELY(not sax->start_object(len)))
        {
            return false;
        }

        string_t key;
        for (std::size_t i = 0; i < len; ++i)
        {
            get();
            if (JSON_UNLIKELY(not get_msgpack_string(key) or not sax->key(key)))
            {
                return false;
            }

            if (JSON_UNLIKELY(not parse_msgpack_internal()))
            {
                return false;
            }
            key.clear();
        }

        return sax->end_object();
    }

    bool get_ubjson_string(string_t& result, const bool get_char = true)
    {
        if (get_char)
        {
            get();        
        }

        if (JSON_UNLIKELY(not unexpect_eof()))
        {
            return false;
        }

        switch (current)
        {
            case 'U':
            {
                uint8_t len;
                return get_number(len) and get_string(len, result);
            }

            case 'i':
            {
                int8_t len;
                return get_number(len) and get_string(len, result);
            }

            case 'I':
            {
                int16_t len;
                return get_number(len) and get_string(len, result);
            }

            case 'l':
            {
                int32_t len;
                return get_number(len) and get_string(len, result);
            }

            case 'L':
            {
                int64_t len;
                return get_number(len) and get_string(len, result);
            }

            default:
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, "expected a UBJSON string; last byte: 0x" + last_token));
        }
    }

    bool get_ubjson_size_value(std::size_t& result)
    {
        switch (get_ignore_noop())
        {
            case 'U':
            {
                uint8_t number;
                if (JSON_UNLIKELY(not get_number(number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'i':
            {
                int8_t number;
                if (JSON_UNLIKELY(not get_number(number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'I':
            {
                int16_t number;
                if (JSON_UNLIKELY(not get_number(number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'l':
            {
                int32_t number;
                if (JSON_UNLIKELY(not get_number(number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            case 'L':
            {
                int64_t number;
                if (JSON_UNLIKELY(not get_number(number)))
                {
                    return false;
                }
                result = static_cast<std::size_t>(number);
                return true;
            }

            default:
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, "byte after '#' must denote a number type; last byte: 0x" + last_token));
            }
        }
    }

    bool get_ubjson_size_type(std::pair<std::size_t, int>& result)
    {
        result.first = string_t::npos;  
        result.second = 0;  

        get_ignore_noop();

        if (current == '$')
        {
            result.second = get();           
            if (JSON_UNLIKELY(not unexpect_eof()))
            {
                return false;
            }

            get_ignore_noop();
            if (JSON_UNLIKELY(current != '#'))
            {
                if (JSON_UNLIKELY(not unexpect_eof()))
                {
                    return false;
                }
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, "expected '#' after UBJSON type information; last byte: 0x" + last_token));
            }

            return get_ubjson_size_value(result.first);
        }
        else if (current == '#')
        {
            return get_ubjson_size_value(result.first);
        }
        return true;
    }

    bool get_ubjson_value(const int prefix)
    {
        switch (prefix)
        {
            case std::char_traits<char>::eof():   
                return unexpect_eof();

            case 'T':   
                return sax->boolean(true);
            case 'F':   
                return sax->boolean(false);

            case 'Z':   
                return sax->null();

            case 'U':
            {
                uint8_t number;
                return get_number(number) and sax->number_unsigned(number);
            }

            case 'i':
            {
                int8_t number;
                return get_number(number) and sax->number_integer(number);
            }

            case 'I':
            {
                int16_t number;
                return get_number(number) and sax->number_integer(number);
            }

            case 'l':
            {
                int32_t number;
                return get_number(number) and sax->number_integer(number);
            }

            case 'L':
            {
                int64_t number;
                return get_number(number) and sax->number_integer(number);
            }

            case 'd':
            {
                float number;
                return get_number(number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 'D':
            {
                double number;
                return get_number(number) and sax->number_float(static_cast<number_float_t>(number), "");
            }

            case 'C':   
            {
                get();
                if (JSON_UNLIKELY(not unexpect_eof()))
                {
                    return false;
                }
                if (JSON_UNLIKELY(current > 127))
                {
                    auto last_token = get_token_string();
                    return sax->parse_error(chars_read, last_token, parse_error::create(113, chars_read, "byte after 'C' must be in range 0x00..0x7F; last byte: 0x" + last_token));
                }
                string_t s(1, static_cast<char>(current));
                return sax->string(s);
            }

            case 'S':   
            {
                string_t s;
                return get_ubjson_string(s) and sax->string(s);
            }

            case '[':   
                return get_ubjson_array();

            case '{':   
                return get_ubjson_object();

            default:   
            {
                auto last_token = get_token_string();
                return sax->parse_error(chars_read, last_token, parse_error::create(112, chars_read, "error reading UBJSON; last byte: 0x" + last_token));
            }
        }
    }

    bool get_ubjson_array()
    {
        std::pair<std::size_t, int> size_and_type;
        if (JSON_UNLIKELY(not get_ubjson_size_type(size_and_type)))
        {
            return false;
        }

        if (size_and_type.first != string_t::npos)
        {
            if (JSON_UNLIKELY(not sax->start_array(size_and_type.first)))
            {
                return false;
            }

            if (size_and_type.second != 0)
            {
                if (size_and_type.second != 'N')
                {
                    for (std::size_t i = 0; i < size_and_type.first; ++i)
                    {
                        if (JSON_UNLIKELY(not get_ubjson_value(size_and_type.second)))
                        {
                            return false;
                        }
                    }
                }
            }
            else
            {
                for (std::size_t i = 0; i < size_and_type.first; ++i)
                {
                    if (JSON_UNLIKELY(not parse_ubjson_internal()))
                    {
                        return false;
                    }
                }
            }
        }
        else
        {
            if (JSON_UNLIKELY(not sax->start_array(std::size_t(-1))))
            {
                return false;
            }

            while (current != ']')
            {
                if (JSON_UNLIKELY(not parse_ubjson_internal(false)))
                {
                    return false;
                }
                get_ignore_noop();
            }
        }

        return sax->end_array();
    }

    bool get_ubjson_object()
    {
        std::pair<std::size_t, int> size_and_type;
        if (JSON_UNLIKELY(not get_ubjson_size_type(size_and_type)))
        {
            return false;
        }

        string_t key;
        if (size_and_type.first != string_t::npos)
        {
            if (JSON_UNLIKELY(not sax->start_object(size_and_type.first)))
            {
                return false;
            }

            if (size_and_type.second != 0)
            {
                for (std::size_t i = 0; i < size_and_type.first; ++i)
                {
                    if (JSON_UNLIKELY(not get_ubjson_string(key) or not sax->key(key)))
                    {
                        return false;
                    }
                    if (JSON_UNLIKELY(not get_ubjson_value(size_and_type.second)))
                    {
                        return false;
                    }
                    key.clear();
                }
            }
            else
            {
                for (std::size_t i = 0; i < size_and_type.first; ++i)
                {
                    if (JSON_UNLIKELY(not get_ubjson_string(key) or not sax->key(key)))
                    {
                        return false;
                    }
                    if (JSON_UNLIKELY(not parse_ubjson_internal()))
                    {
                        return false;
                    }
                    key.clear();
                }
            }
        }
        else
        {
            if (JSON_UNLIKELY(not sax->start_object(std::size_t(-1))))
            {
                return false;
            }

            while (current != '}')
            {
                if (JSON_UNLIKELY(not get_ubjson_string(key, false) or not sax->key(key)))
                {
                    return false;
                }
                if (JSON_UNLIKELY(not parse_ubjson_internal()))
                {
                    return false;
                }
                get_ignore_noop();
                key.clear();
            }
        }

        return sax->end_object();
    }

    bool unexpect_eof() const
    {
        if (JSON_UNLIKELY(current == std::char_traits<char>::eof()))
        {
            return sax->parse_error(chars_read, "<end of file>", parse_error::create(110, chars_read, "unexpected end of input"));
        }
        return true;
    }

    std::string get_token_string() const
    {
        char cr[3];
        snprintf(cr, 3, "%.2hhX", static_cast<unsigned char>(current));
        return std::string{cr};
    }

  private:
    input_adapter_t ia = nullptr;

    int current = std::char_traits<char>::eof();

    std::size_t chars_read = 0;

    const bool is_little_endian = little_endianess();

    json_sax_t* sax = nullptr;
};
}
}


#include <algorithm>  
#include <array>  
#include <cstdint>     
#include <cstring>  
#include <limits>  


namespace nlohmann
{
namespace detail
{
template<typename BasicJsonType, typename CharType>
class binary_writer
{
  public:
    explicit binary_writer(output_adapter_t<CharType> adapter) : oa(adapter)
    {
        assert(oa);
    }

    void write_cbor(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::null:
            {
                oa->write_character(static_cast<CharType>(0xF6));
                break;
            }

            case value_t::boolean:
            {
                oa->write_character(j.m_value.boolean
                                    ? static_cast<CharType>(0xF5)
                                    : static_cast<CharType>(0xF4));
                break;
            }

            case value_t::number_integer:
            {
                if (j.m_value.number_integer >= 0)
                {
                    if (j.m_value.number_integer <= 0x17)
                    {
                        write_number(static_cast<uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer <= (std::numeric_limits<uint8_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x18));
                        write_number(static_cast<uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer <= (std::numeric_limits<uint16_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x19));
                        write_number(static_cast<uint16_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer <= (std::numeric_limits<uint32_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x1A));
                        write_number(static_cast<uint32_t>(j.m_value.number_integer));
                    }
                    else
                    {
                        oa->write_character(static_cast<CharType>(0x1B));
                        write_number(static_cast<uint64_t>(j.m_value.number_integer));
                    }
                }
                else
                {
                    const auto positive_number = -1 - j.m_value.number_integer;
                    if (j.m_value.number_integer >= -24)
                    {
                        write_number(static_cast<uint8_t>(0x20 + positive_number));
                    }
                    else if (positive_number <= (std::numeric_limits<uint8_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x38));
                        write_number(static_cast<uint8_t>(positive_number));
                    }
                    else if (positive_number <= (std::numeric_limits<uint16_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x39));
                        write_number(static_cast<uint16_t>(positive_number));
                    }
                    else if (positive_number <= (std::numeric_limits<uint32_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0x3A));
                        write_number(static_cast<uint32_t>(positive_number));
                    }
                    else
                    {
                        oa->write_character(static_cast<CharType>(0x3B));
                        write_number(static_cast<uint64_t>(positive_number));
                    }
                }
                break;
            }

            case value_t::number_unsigned:
            {
                if (j.m_value.number_unsigned <= 0x17)
                {
                    write_number(static_cast<uint8_t>(j.m_value.number_unsigned));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x18));
                    write_number(static_cast<uint8_t>(j.m_value.number_unsigned));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x19));
                    write_number(static_cast<uint16_t>(j.m_value.number_unsigned));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x1A));
                    write_number(static_cast<uint32_t>(j.m_value.number_unsigned));
                }
                else
                {
                    oa->write_character(static_cast<CharType>(0x1B));
                    write_number(static_cast<uint64_t>(j.m_value.number_unsigned));
                }
                break;
            }

            case value_t::number_float:
            {
                oa->write_character(get_cbor_float_prefix(j.m_value.number_float));
                write_number(j.m_value.number_float);
                break;
            }

            case value_t::string:
            {
                const auto N = j.m_value.string->size();
                if (N <= 0x17)
                {
                    write_number(static_cast<uint8_t>(0x60 + N));
                }
                else if (N <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x78));
                    write_number(static_cast<uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x79));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x7A));
                    write_number(static_cast<uint32_t>(N));
                }
                else if (N <= (std::numeric_limits<uint64_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x7B));
                    write_number(static_cast<uint64_t>(N));
                }
                oa->write_characters(
                    reinterpret_cast<const CharType*>(j.m_value.string->c_str()),
                    j.m_value.string->size());
                break;
            }

            case value_t::array:
            {
                const auto N = j.m_value.array->size();
                if (N <= 0x17)
                {
                    write_number(static_cast<uint8_t>(0x80 + N));
                }
                else if (N <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x98));
                    write_number(static_cast<uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x99));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x9A));
                    write_number(static_cast<uint32_t>(N));
                }
                else if (N <= (std::numeric_limits<uint64_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0x9B));
                    write_number(static_cast<uint64_t>(N));
                }
                for (const auto& el : *j.m_value.array)
                {
                    write_cbor(el);
                }
                break;
            }

            case value_t::object:
            {
                const auto N = j.m_value.object->size();
                if (N <= 0x17)
                {
                    write_number(static_cast<uint8_t>(0xA0 + N));
                }
                else if (N <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xB8));
                    write_number(static_cast<uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xB9));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xBA));
                    write_number(static_cast<uint32_t>(N));
                }
                else if (N <= (std::numeric_limits<uint64_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xBB));
                    write_number(static_cast<uint64_t>(N));
                }
                for (const auto& el : *j.m_value.object)
                {
                    write_cbor(el.first);
                    write_cbor(el.second);
                }
                break;
            }

            default:
                break;
        }
    }

    void write_msgpack(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::null:  
            {
                oa->write_character(static_cast<CharType>(0xC0));
                break;
            }

            case value_t::boolean:    
            {
                oa->write_character(j.m_value.boolean
                                    ? static_cast<CharType>(0xC3)
                                    : static_cast<CharType>(0xC2));
                break;
            }

            case value_t::number_integer:
            {
                if (j.m_value.number_integer >= 0)
                {
                    if (j.m_value.number_unsigned < 128)
                    {
                        write_number(static_cast<uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<uint8_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0xCC));
                        write_number(static_cast<uint8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<uint16_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0xCD));
                        write_number(static_cast<uint16_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<uint32_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0xCE));
                        write_number(static_cast<uint32_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_unsigned <= (std::numeric_limits<uint64_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0xCF));
                        write_number(static_cast<uint64_t>(j.m_value.number_integer));
                    }
                }
                else
                {
                    if (j.m_value.number_integer >= -32)
                    {
                        write_number(static_cast<int8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<int8_t>::min)() and
                             j.m_value.number_integer <= (std::numeric_limits<int8_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0xD0));
                        write_number(static_cast<int8_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<int16_t>::min)() and
                             j.m_value.number_integer <= (std::numeric_limits<int16_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0xD1));
                        write_number(static_cast<int16_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<int32_t>::min)() and
                             j.m_value.number_integer <= (std::numeric_limits<int32_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0xD2));
                        write_number(static_cast<int32_t>(j.m_value.number_integer));
                    }
                    else if (j.m_value.number_integer >= (std::numeric_limits<int64_t>::min)() and
                             j.m_value.number_integer <= (std::numeric_limits<int64_t>::max)())
                    {
                        oa->write_character(static_cast<CharType>(0xD3));
                        write_number(static_cast<int64_t>(j.m_value.number_integer));
                    }
                }
                break;
            }

            case value_t::number_unsigned:
            {
                if (j.m_value.number_unsigned < 128)
                {
                    write_number(static_cast<uint8_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xCC));
                    write_number(static_cast<uint8_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xCD));
                    write_number(static_cast<uint16_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xCE));
                    write_number(static_cast<uint32_t>(j.m_value.number_integer));
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint64_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xCF));
                    write_number(static_cast<uint64_t>(j.m_value.number_integer));
                }
                break;
            }

            case value_t::number_float:
            {
                oa->write_character(get_msgpack_float_prefix(j.m_value.number_float));
                write_number(j.m_value.number_float);
                break;
            }

            case value_t::string:
            {
                const auto N = j.m_value.string->size();
                if (N <= 31)
                {
                    write_number(static_cast<uint8_t>(0xA0 | N));
                }
                else if (N <= (std::numeric_limits<uint8_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xD9));
                    write_number(static_cast<uint8_t>(N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xDA));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xDB));
                    write_number(static_cast<uint32_t>(N));
                }

                oa->write_characters(
                    reinterpret_cast<const CharType*>(j.m_value.string->c_str()),
                    j.m_value.string->size());
                break;
            }

            case value_t::array:
            {
                const auto N = j.m_value.array->size();
                if (N <= 15)
                {
                    write_number(static_cast<uint8_t>(0x90 | N));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xDC));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xDD));
                    write_number(static_cast<uint32_t>(N));
                }

                for (const auto& el : *j.m_value.array)
                {
                    write_msgpack(el);
                }
                break;
            }

            case value_t::object:
            {
                const auto N = j.m_value.object->size();
                if (N <= 15)
                {
                    write_number(static_cast<uint8_t>(0x80 | (N & 0xF)));
                }
                else if (N <= (std::numeric_limits<uint16_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xDE));
                    write_number(static_cast<uint16_t>(N));
                }
                else if (N <= (std::numeric_limits<uint32_t>::max)())
                {
                    oa->write_character(static_cast<CharType>(0xDF));
                    write_number(static_cast<uint32_t>(N));
                }

                for (const auto& el : *j.m_value.object)
                {
                    write_msgpack(el.first);
                    write_msgpack(el.second);
                }
                break;
            }

            default:
                break;
        }
    }

    void write_ubjson(const BasicJsonType& j, const bool use_count,
                      const bool use_type, const bool add_prefix = true)
    {
        switch (j.type())
        {
            case value_t::null:
            {
                if (add_prefix)
                {
                    oa->write_character(static_cast<CharType>('Z'));
                }
                break;
            }

            case value_t::boolean:
            {
                if (add_prefix)
                    oa->write_character(j.m_value.boolean
                                        ? static_cast<CharType>('T')
                                        : static_cast<CharType>('F'));
                break;
            }

            case value_t::number_integer:
            {
                write_number_with_ubjson_prefix(j.m_value.number_integer, add_prefix);
                break;
            }

            case value_t::number_unsigned:
            {
                write_number_with_ubjson_prefix(j.m_value.number_unsigned, add_prefix);
                break;
            }

            case value_t::number_float:
            {
                write_number_with_ubjson_prefix(j.m_value.number_float, add_prefix);
                break;
            }

            case value_t::string:
            {
                if (add_prefix)
                {
                    oa->write_character(static_cast<CharType>('S'));
                }
                write_number_with_ubjson_prefix(j.m_value.string->size(), true);
                oa->write_characters(
                    reinterpret_cast<const CharType*>(j.m_value.string->c_str()),
                    j.m_value.string->size());
                break;
            }

            case value_t::array:
            {
                if (add_prefix)
                {
                    oa->write_character(static_cast<CharType>('['));
                }

                bool prefix_required = true;
                if (use_type and not j.m_value.array->empty())
                {
                    assert(use_count);
                    const CharType first_prefix = ubjson_prefix(j.front());
                    const bool same_prefix = std::all_of(j.begin() + 1, j.end(),
                                                         [this, first_prefix](const BasicJsonType & v)
                    {
                        return ubjson_prefix(v) == first_prefix;
                    });

                    if (same_prefix)
                    {
                        prefix_required = false;
                        oa->write_character(static_cast<CharType>('$'));
                        oa->write_character(first_prefix);
                    }
                }

                if (use_count)
                {
                    oa->write_character(static_cast<CharType>('#'));
                    write_number_with_ubjson_prefix(j.m_value.array->size(), true);
                }

                for (const auto& el : *j.m_value.array)
                {
                    write_ubjson(el, use_count, use_type, prefix_required);
                }

                if (not use_count)
                {
                    oa->write_character(static_cast<CharType>(']'));
                }

                break;
            }

            case value_t::object:
            {
                if (add_prefix)
                {
                    oa->write_character(static_cast<CharType>('{'));
                }

                bool prefix_required = true;
                if (use_type and not j.m_value.object->empty())
                {
                    assert(use_count);
                    const CharType first_prefix = ubjson_prefix(j.front());
                    const bool same_prefix = std::all_of(j.begin(), j.end(),
                                                         [this, first_prefix](const BasicJsonType & v)
                    {
                        return ubjson_prefix(v) == first_prefix;
                    });

                    if (same_prefix)
                    {
                        prefix_required = false;
                        oa->write_character(static_cast<CharType>('$'));
                        oa->write_character(first_prefix);
                    }
                }

                if (use_count)
                {
                    oa->write_character(static_cast<CharType>('#'));
                    write_number_with_ubjson_prefix(j.m_value.object->size(), true);
                }

                for (const auto& el : *j.m_value.object)
                {
                    write_number_with_ubjson_prefix(el.first.size(), true);
                    oa->write_characters(
                        reinterpret_cast<const CharType*>(el.first.c_str()),
                        el.first.size());
                    write_ubjson(el.second, use_count, use_type, prefix_required);
                }

                if (not use_count)
                {
                    oa->write_character(static_cast<CharType>('}'));
                }

                break;
            }

            default:
                break;
        }
    }

  private:
    template<typename NumberType>
    void write_number(const NumberType n)
    {
        std::array<CharType, sizeof(NumberType)> vec;
        std::memcpy(vec.data(), &n, sizeof(NumberType));

        if (is_little_endian)
        {
            std::reverse(vec.begin(), vec.end());
        }

        oa->write_characters(vec.data(), sizeof(NumberType));
    }

    template<typename NumberType, typename std::enable_if<
                 std::is_floating_point<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix)
    {
        if (add_prefix)
        {
            oa->write_character(get_ubjson_float_prefix(n));
        }
        write_number(n);
    }

    template<typename NumberType, typename std::enable_if<
                 std::is_unsigned<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix)
    {
        if (n <= static_cast<uint64_t>((std::numeric_limits<int8_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('i'));   
            }
            write_number(static_cast<uint8_t>(n));
        }
        else if (n <= (std::numeric_limits<uint8_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('U'));   
            }
            write_number(static_cast<uint8_t>(n));
        }
        else if (n <= static_cast<uint64_t>((std::numeric_limits<int16_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('I'));   
            }
            write_number(static_cast<int16_t>(n));
        }
        else if (n <= static_cast<uint64_t>((std::numeric_limits<int32_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('l'));   
            }
            write_number(static_cast<int32_t>(n));
        }
        else if (n <= static_cast<uint64_t>((std::numeric_limits<int64_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('L'));   
            }
            write_number(static_cast<int64_t>(n));
        }
        else
        {
            JSON_THROW(out_of_range::create(407, "number overflow serializing " + std::to_string(n)));
        }
    }

    template<typename NumberType, typename std::enable_if<
                 std::is_signed<NumberType>::value and
                 not std::is_floating_point<NumberType>::value, int>::type = 0>
    void write_number_with_ubjson_prefix(const NumberType n,
                                         const bool add_prefix)
    {
        if ((std::numeric_limits<int8_t>::min)() <= n and n <= (std::numeric_limits<int8_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('i'));   
            }
            write_number(static_cast<int8_t>(n));
        }
        else if (static_cast<int64_t>((std::numeric_limits<uint8_t>::min)()) <= n and n <= static_cast<int64_t>((std::numeric_limits<uint8_t>::max)()))
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('U'));   
            }
            write_number(static_cast<uint8_t>(n));
        }
        else if ((std::numeric_limits<int16_t>::min)() <= n and n <= (std::numeric_limits<int16_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('I'));   
            }
            write_number(static_cast<int16_t>(n));
        }
        else if ((std::numeric_limits<int32_t>::min)() <= n and n <= (std::numeric_limits<int32_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('l'));   
            }
            write_number(static_cast<int32_t>(n));
        }
        else if ((std::numeric_limits<int64_t>::min)() <= n and n <= (std::numeric_limits<int64_t>::max)())
        {
            if (add_prefix)
            {
                oa->write_character(static_cast<CharType>('L'));   
            }
            write_number(static_cast<int64_t>(n));
        }
        else
        {
            JSON_THROW(out_of_range::create(407, "number overflow serializing " + std::to_string(n)));
        }
    }

    CharType ubjson_prefix(const BasicJsonType& j) const noexcept
    {
        switch (j.type())
        {
            case value_t::null:
                return 'Z';

            case value_t::boolean:
                return j.m_value.boolean ? 'T' : 'F';

            case value_t::number_integer:
            {
                if ((std::numeric_limits<int8_t>::min)() <= j.m_value.number_integer and j.m_value.number_integer <= (std::numeric_limits<int8_t>::max)())
                {
                    return 'i';
                }
                else if ((std::numeric_limits<uint8_t>::min)() <= j.m_value.number_integer and j.m_value.number_integer <= (std::numeric_limits<uint8_t>::max)())
                {
                    return 'U';
                }
                else if ((std::numeric_limits<int16_t>::min)() <= j.m_value.number_integer and j.m_value.number_integer <= (std::numeric_limits<int16_t>::max)())
                {
                    return 'I';
                }
                else if ((std::numeric_limits<int32_t>::min)() <= j.m_value.number_integer and j.m_value.number_integer <= (std::numeric_limits<int32_t>::max)())
                {
                    return 'l';
                }
                else          
                {
                    return 'L';
                }
            }

            case value_t::number_unsigned:
            {
                if (j.m_value.number_unsigned <= (std::numeric_limits<int8_t>::max)())
                {
                    return 'i';
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<uint8_t>::max)())
                {
                    return 'U';
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<int16_t>::max)())
                {
                    return 'I';
                }
                else if (j.m_value.number_unsigned <= (std::numeric_limits<int32_t>::max)())
                {
                    return 'l';
                }
                else          
                {
                    return 'L';
                }
            }

            case value_t::number_float:
                return get_ubjson_float_prefix(j.m_value.number_float);

            case value_t::string:
                return 'S';

            case value_t::array:
                return '[';

            case value_t::object:
                return '{';

            default:    
                return 'N';
        }
    }

    static constexpr CharType get_cbor_float_prefix(float)
    {
        return static_cast<CharType>(0xFA);    
    }

    static constexpr CharType get_cbor_float_prefix(double)
    {
        return static_cast<CharType>(0xFB);    
    }

    static constexpr CharType get_msgpack_float_prefix(float)
    {
        return static_cast<CharType>(0xCA);    
    }

    static constexpr CharType get_msgpack_float_prefix(double)
    {
        return static_cast<CharType>(0xCB);    
    }

    static constexpr CharType get_ubjson_float_prefix(float)
    {
        return 'd';    
    }

    static constexpr CharType get_ubjson_float_prefix(double)
    {
        return 'D';    
    }

  private:
    const bool is_little_endian = binary_reader<BasicJsonType>::little_endianess();

    output_adapter_t<CharType> oa = nullptr;
};
}
}


#include <algorithm>      
#include <array>  
#include <cassert>  
#include <ciso646>   
#include <clocale>   
#include <cmath>     
#include <cstddef>   
#include <cstdint>  
#include <cstdio>  
#include <limits>  
#include <string>  
#include <type_traits>  
#include <cassert>  
#include <ciso646>    
#include <cmath>     
#include <cstdint>   
#include <cstring>   

namespace nlohmann
{
namespace detail
{
namespace dtoa_impl
{

template <typename Target, typename Source>
Target reinterpret_bits(const Source source)
{
    static_assert(sizeof(Target) == sizeof(Source), "size mismatch");

    Target target;
    std::memcpy(&target, &source, sizeof(Source));
    return target;
}

struct diyfp    
{
    static constexpr int kPrecision = 64;   

    uint64_t f;
    int e;

    constexpr diyfp() noexcept : f(0), e(0) {}
    constexpr diyfp(uint64_t f_, int e_) noexcept : f(f_), e(e_) {}

    static diyfp sub(const diyfp& x, const diyfp& y) noexcept
    {
        assert(x.e == y.e);
        assert(x.f >= y.f);

        return diyfp(x.f - y.f, x.e);
    }

    static diyfp mul(const diyfp& x, const diyfp& y) noexcept
    {
        static_assert(kPrecision == 64, "internal error");

        const uint64_t u_lo = x.f & 0xFFFFFFFF;
        const uint64_t u_hi = x.f >> 32;
        const uint64_t v_lo = y.f & 0xFFFFFFFF;
        const uint64_t v_hi = y.f >> 32;

        const uint64_t p0 = u_lo * v_lo;
        const uint64_t p1 = u_lo * v_hi;
        const uint64_t p2 = u_hi * v_lo;
        const uint64_t p3 = u_hi * v_hi;

        const uint64_t p0_hi = p0 >> 32;
        const uint64_t p1_lo = p1 & 0xFFFFFFFF;
        const uint64_t p1_hi = p1 >> 32;
        const uint64_t p2_lo = p2 & 0xFFFFFFFF;
        const uint64_t p2_hi = p2 >> 32;

        uint64_t Q = p0_hi + p1_lo + p2_lo;

        Q += uint64_t{1} << (64 - 32 - 1);    

        const uint64_t h = p3 + p2_hi + p1_hi + (Q >> 32);

        return diyfp(h, x.e + y.e + 64);
    }
    static diyfp normalize(diyfp x) noexcept
    {
        assert(x.f != 0);

        while ((x.f >> 63) == 0)
        {
            x.f <<= 1;
            x.e--;
        }

        return x;
    }
    static diyfp normalize_to(const diyfp& x, const int target_exponent) noexcept
    {
        const int delta = x.e - target_exponent;

        assert(delta >= 0);
        assert(((x.f << delta) >> delta) == x.f);

        return diyfp(x.f << delta, target_exponent);
    }
};

struct boundaries
{
    diyfp w;
    diyfp minus;
    diyfp plus;
};
template <typename FloatType>
boundaries compute_boundaries(FloatType value)
{
    assert(std::isfinite(value));
    assert(value > 0);
    static_assert(std::numeric_limits<FloatType>::is_iec559,
                  "internal error: dtoa_short requires an IEEE-754 floating-point implementation");

    constexpr int      kPrecision = std::numeric_limits<FloatType>::digits;       
    constexpr int      kBias      = std::numeric_limits<FloatType>::max_exponent - 1 + (kPrecision - 1);
    constexpr int      kMinExp    = 1 - kBias;
    constexpr uint64_t kHiddenBit = uint64_t{1} << (kPrecision - 1);   

    using bits_type = typename std::conditional< kPrecision == 24, uint32_t, uint64_t >::type;

    const uint64_t bits = reinterpret_bits<bits_type>(value);
    const uint64_t E = bits >> (kPrecision - 1);
    const uint64_t F = bits & (kHiddenBit - 1);

    const bool is_denormal = (E == 0);
    const diyfp v = is_denormal
                    ? diyfp(F, kMinExp)
                    : diyfp(F + kHiddenBit, static_cast<int>(E) - kBias);

    
    const bool lower_boundary_is_closer = (F == 0 and E > 1);
    const diyfp m_plus = diyfp(2 * v.f + 1, v.e - 1);
    const diyfp m_minus = lower_boundary_is_closer
                          ? diyfp(4 * v.f - 1, v.e - 2)   
                          : diyfp(2 * v.f - 1, v.e - 1);  

    const diyfp w_plus = diyfp::normalize(m_plus);

    const diyfp w_minus = diyfp::normalize_to(m_minus, w_plus.e);

    return {diyfp::normalize(v), w_minus, w_plus};
}

constexpr int kAlpha = -60;
constexpr int kGamma = -32;

struct cached_power        
{
    uint64_t f;
    int e;
    int k;
};

inline cached_power get_cached_power_for_binary_exponent(int e)
{
    constexpr int kCachedPowersSize = 79;
    constexpr int kCachedPowersMinDecExp = -300;
    constexpr int kCachedPowersDecStep = 8;

    static constexpr cached_power kCachedPowers[] =
    {
        { 0xAB70FE17C79AC6CA, -1060, -300 },
        { 0xFF77B1FCBEBCDC4F, -1034, -292 },
        { 0xBE5691EF416BD60C, -1007, -284 },
        { 0x8DD01FAD907FFC3C,  -980, -276 },
        { 0xD3515C2831559A83,  -954, -268 },
        { 0x9D71AC8FADA6C9B5,  -927, -260 },
        { 0xEA9C227723EE8BCB,  -901, -252 },
        { 0xAECC49914078536D,  -874, -244 },
        { 0x823C12795DB6CE57,  -847, -236 },
        { 0xC21094364DFB5637,  -821, -228 },
        { 0x9096EA6F3848984F,  -794, -220 },
        { 0xD77485CB25823AC7,  -768, -212 },
        { 0xA086CFCD97BF97F4,  -741, -204 },
        { 0xEF340A98172AACE5,  -715, -196 },
        { 0xB23867FB2A35B28E,  -688, -188 },
        { 0x84C8D4DFD2C63F3B,  -661, -180 },
        { 0xC5DD44271AD3CDBA,  -635, -172 },
        { 0x936B9FCEBB25C996,  -608, -164 },
        { 0xDBAC6C247D62A584,  -582, -156 },
        { 0xA3AB66580D5FDAF6,  -555, -148 },
        { 0xF3E2F893DEC3F126,  -529, -140 },
        { 0xB5B5ADA8AAFF80B8,  -502, -132 },
        { 0x87625F056C7C4A8B,  -475, -124 },
        { 0xC9BCFF6034C13053,  -449, -116 },
        { 0x964E858C91BA2655,  -422, -108 },
        { 0xDFF9772470297EBD,  -396, -100 },
        { 0xA6DFBD9FB8E5B88F,  -369,  -92 },
        { 0xF8A95FCF88747D94,  -343,  -84 },
        { 0xB94470938FA89BCF,  -316,  -76 },
        { 0x8A08F0F8BF0F156B,  -289,  -68 },
        { 0xCDB02555653131B6,  -263,  -60 },
        { 0x993FE2C6D07B7FAC,  -236,  -52 },
        { 0xE45C10C42A2B3B06,  -210,  -44 },
        { 0xAA242499697392D3,  -183,  -36 },
        { 0xFD87B5F28300CA0E,  -157,  -28 },
        { 0xBCE5086492111AEB,  -130,  -20 },
        { 0x8CBCCC096F5088CC,  -103,  -12 },
        { 0xD1B71758E219652C,   -77,   -4 },
        { 0x9C40000000000000,   -50,    4 },
        { 0xE8D4A51000000000,   -24,   12 },
        { 0xAD78EBC5AC620000,     3,   20 },
        { 0x813F3978F8940984,    30,   28 },
        { 0xC097CE7BC90715B3,    56,   36 },
        { 0x8F7E32CE7BEA5C70,    83,   44 },
        { 0xD5D238A4ABE98068,   109,   52 },
        { 0x9F4F2726179A2245,   136,   60 },
        { 0xED63A231D4C4FB27,   162,   68 },
        { 0xB0DE65388CC8ADA8,   189,   76 },
        { 0x83C7088E1AAB65DB,   216,   84 },
        { 0xC45D1DF942711D9A,   242,   92 },
        { 0x924D692CA61BE758,   269,  100 },
        { 0xDA01EE641A708DEA,   295,  108 },
        { 0xA26DA3999AEF774A,   322,  116 },
        { 0xF209787BB47D6B85,   348,  124 },
        { 0xB454E4A179DD1877,   375,  132 },
        { 0x865B86925B9BC5C2,   402,  140 },
        { 0xC83553C5C8965D3D,   428,  148 },
        { 0x952AB45CFA97A0B3,   455,  156 },
        { 0xDE469FBD99A05FE3,   481,  164 },
        { 0xA59BC234DB398C25,   508,  172 },
        { 0xF6C69A72A3989F5C,   534,  180 },
        { 0xB7DCBF5354E9BECE,   561,  188 },
        { 0x88FCF317F22241E2,   588,  196 },
        { 0xCC20CE9BD35C78A5,   614,  204 },
        { 0x98165AF37B2153DF,   641,  212 },
        { 0xE2A0B5DC971F303A,   667,  220 },
        { 0xA8D9D1535CE3B396,   694,  228 },
        { 0xFB9B7CD9A4A7443C,   720,  236 },
        { 0xBB764C4CA7A44410,   747,  244 },
        { 0x8BAB8EEFB6409C1A,   774,  252 },
        { 0xD01FEF10A657842C,   800,  260 },
        { 0x9B10A4E5E9913129,   827,  268 },
        { 0xE7109BFBA19C0C9D,   853,  276 },
        { 0xAC2820D9623BF429,   880,  284 },
        { 0x80444B5E7AA7CF85,   907,  292 },
        { 0xBF21E44003ACDD2D,   933,  300 },
        { 0x8E679C2F5E44FF8F,   960,  308 },
        { 0xD433179D9C8CB841,   986,  316 },
        { 0x9E19DB92B4E31BA9,  1013,  324 },
    };

    assert(e >= -1500);
    assert(e <=  1500);
    const int f = kAlpha - e - 1;
    const int k = (f * 78913) / (1 << 18) + (f > 0);

    const int index = (-kCachedPowersMinDecExp + k + (kCachedPowersDecStep - 1)) / kCachedPowersDecStep;
    assert(index >= 0);
    assert(index < kCachedPowersSize);
    static_cast<void>(kCachedPowersSize);   

    const cached_power cached = kCachedPowers[index];
    assert(kAlpha <= cached.e + e + 64);
    assert(kGamma >= cached.e + e + 64);

    return cached;
}

inline int find_largest_pow10(const uint32_t n, uint32_t& pow10)
{
    if (n >= 1000000000)
    {
        pow10 = 1000000000;
        return 10;
    }
    else if (n >= 100000000)
    {
        pow10 = 100000000;
        return  9;
    }
    else if (n >= 10000000)
    {
        pow10 = 10000000;
        return  8;
    }
    else if (n >= 1000000)
    {
        pow10 = 1000000;
        return  7;
    }
    else if (n >= 100000)
    {
        pow10 = 100000;
        return  6;
    }
    else if (n >= 10000)
    {
        pow10 = 10000;
        return  5;
    }
    else if (n >= 1000)
    {
        pow10 = 1000;
        return  4;
    }
    else if (n >= 100)
    {
        pow10 = 100;
        return  3;
    }
    else if (n >= 10)
    {
        pow10 = 10;
        return  2;
    }
    else
    {
        pow10 = 1;
        return 1;
    }
}

inline void grisu2_round(char* buf, int len, uint64_t dist, uint64_t delta,
                         uint64_t rest, uint64_t ten_k)
{
    assert(len >= 1);
    assert(dist <= delta);
    assert(rest <= delta);
    assert(ten_k > 0);

    while (rest < dist
            and delta - rest >= ten_k
            and (rest + ten_k < dist or dist - rest > rest + ten_k - dist))
    {
        assert(buf[len - 1] != '0');
        buf[len - 1]--;
        rest += ten_k;
    }
}

inline void grisu2_digit_gen(char* buffer, int& length, int& decimal_exponent,
                             diyfp M_minus, diyfp w, diyfp M_plus)
{
    static_assert(kAlpha >= -60, "internal error");
    static_assert(kGamma <= -32, "internal error");

    assert(M_plus.e >= kAlpha);
    assert(M_plus.e <= kGamma);

    uint64_t delta = diyfp::sub(M_plus, M_minus).f;          
    uint64_t dist  = diyfp::sub(M_plus, w      ).f;           

    const diyfp one(uint64_t{1} << -M_plus.e, M_plus.e);

    uint32_t p1 = static_cast<uint32_t>(M_plus.f >> -one.e);                
    uint64_t p2 = M_plus.f & (one.f - 1);                         

    assert(p1 > 0);

    uint32_t pow10;
    const int k = find_largest_pow10(p1, pow10);

    int n = k;
    while (n > 0)
    {
        const uint32_t d = p1 / pow10;       
        const uint32_t r = p1 % pow10;       
        assert(d <= 9);
        buffer[length++] = static_cast<char>('0' + d);        
        p1 = r;
        n--;
        const uint64_t rest = (uint64_t{p1} << -one.e) + p2;
        if (rest <= delta)
        {
            decimal_exponent += n;

            const uint64_t ten_n = uint64_t{pow10} << -one.e;
            grisu2_round(buffer, length, dist, delta, rest, ten_n);

            return;
        }

        pow10 /= 10;
    }
    assert(p2 > delta);

    int m = 0;
    for (;;)
    {
        assert(p2 <= UINT64_MAX / 10);
        p2 *= 10;
        const uint64_t d = p2 >> -one.e;            
        const uint64_t r = p2 & (one.f - 1);        
        assert(d <= 9);
        buffer[length++] = static_cast<char>('0' + d);        
        p2 = r;
        m++;
        delta *= 10;
        dist  *= 10;
        if (p2 <= delta)
        {
            break;
        }
    }
    decimal_exponent -= m;
    const uint64_t ten_m = one.f;
    grisu2_round(buffer, length, dist, delta, p2, ten_m);
}
inline void grisu2(char* buf, int& len, int& decimal_exponent,
                   diyfp m_minus, diyfp v, diyfp m_plus)
{
    assert(m_plus.e == m_minus.e);
    assert(m_plus.e == v.e);
    const cached_power cached = get_cached_power_for_binary_exponent(m_plus.e);

    const diyfp c_minus_k(cached.f, cached.e);     

    const diyfp w       = diyfp::mul(v,       c_minus_k);
    const diyfp w_minus = diyfp::mul(m_minus, c_minus_k);
    const diyfp w_plus  = diyfp::mul(m_plus,  c_minus_k);
    const diyfp M_minus(w_minus.f + 1, w_minus.e);
    const diyfp M_plus (w_plus.f  - 1, w_plus.e );

    decimal_exponent = -cached.k;     

    grisu2_digit_gen(buf, len, decimal_exponent, M_minus, w, M_plus);
}
template <typename FloatType>
void grisu2(char* buf, int& len, int& decimal_exponent, FloatType value)
{
    static_assert(diyfp::kPrecision >= std::numeric_limits<FloatType>::digits + 3,
                  "internal error: not enough precision");

    assert(std::isfinite(value));
    assert(value > 0);
#if 0
    const boundaries w = compute_boundaries(static_cast<double>(value));
#else
    const boundaries w = compute_boundaries(value);
#endif

    grisu2(buf, len, decimal_exponent, w.minus, w.w, w.plus);
}
inline char* append_exponent(char* buf, int e)
{
    assert(e > -1000);
    assert(e <  1000);

    if (e < 0)
    {
        e = -e;
        *buf++ = '-';
    }
    else
    {
        *buf++ = '+';
    }

    uint32_t k = static_cast<uint32_t>(e);
    if (k < 10)
    {
        *buf++ = '0';
        *buf++ = static_cast<char>('0' + k);
    }
    else if (k < 100)
    {
        *buf++ = static_cast<char>('0' + k / 10);
        k %= 10;
        *buf++ = static_cast<char>('0' + k);
    }
    else
    {
        *buf++ = static_cast<char>('0' + k / 100);
        k %= 100;
        *buf++ = static_cast<char>('0' + k / 10);
        k %= 10;
        *buf++ = static_cast<char>('0' + k);
    }

    return buf;
}
inline char* format_buffer(char* buf, int len, int decimal_exponent,
                           int min_exp, int max_exp)
{
    assert(min_exp < 0);
    assert(max_exp > 0);

    const int k = len;
    const int n = len + decimal_exponent;
    if (k <= n and n <= max_exp)
    {
        std::memset(buf + k, '0', static_cast<size_t>(n - k));
        buf[n + 0] = '.';
        buf[n + 1] = '0';
        return buf + (n + 2);
    }

    if (0 < n and n <= max_exp)
    {
        assert(k > n);

        std::memmove(buf + (n + 1), buf + n, static_cast<size_t>(k - n));
        buf[n] = '.';
        return buf + (k + 1);
    }

    if (min_exp < n and n <= 0)
    {
        std::memmove(buf + (2 + -n), buf, static_cast<size_t>(k));
        buf[0] = '0';
        buf[1] = '.';
        std::memset(buf + 2, '0', static_cast<size_t>(-n));
        return buf + (2 + (-n) + k);
    }

    if (k == 1)
    {
        buf += 1;
    }
    else
    {
        std::memmove(buf + 2, buf + 1, static_cast<size_t>(k - 1));
        buf[1] = '.';
        buf += 1 + k;
    }

    *buf++ = 'e';
    return append_exponent(buf, n - 1);
}
}
template <typename FloatType>
char* to_chars(char* first, char* last, FloatType value)
{
    static_cast<void>(last);      
    assert(std::isfinite(value));
    if (std::signbit(value))
    {
        value = -value;
        *first++ = '-';
    }

    if (value == 0)  
    {
        *first++ = '0';
        *first++ = '.';
        *first++ = '0';
        return first;
    }
    assert(last - first >= std::numeric_limits<FloatType>::max_digits10);
    int len = 0;
    int decimal_exponent = 0;
    dtoa_impl::grisu2(first, len, decimal_exponent, value);

    assert(len <= std::numeric_limits<FloatType>::max_digits10);

    constexpr int kMinExp = -4;
    constexpr int kMaxExp = std::numeric_limits<FloatType>::digits10;

    assert(last - first >= kMaxExp + 2);
    assert(last - first >= 2 + (-kMinExp - 1) + std::numeric_limits<FloatType>::max_digits10);
    assert(last - first >= std::numeric_limits<FloatType>::max_digits10 + 6);

    return dtoa_impl::format_buffer(first, len, decimal_exponent, kMinExp, kMaxExp);
}

}   
}   


namespace nlohmann
{
namespace detail
{
template<typename BasicJsonType>
class serializer
{
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    static constexpr uint8_t UTF8_ACCEPT = 0;
    static constexpr uint8_t UTF8_REJECT = 1;

  public:
    serializer(output_adapter_t<char> s, const char ichar)
        : o(std::move(s)), loc(std::localeconv()),
          thousands_sep(loc->thousands_sep == nullptr ? '\0' : * (loc->thousands_sep)),
          decimal_point(loc->decimal_point == nullptr ? '\0' : * (loc->decimal_point)),
          indent_char(ichar), indent_string(512, indent_char)
    {}

    serializer(const serializer&) = delete;
    serializer& operator=(const serializer&) = delete;

    void dump(const BasicJsonType& val, const bool pretty_print,
              const bool ensure_ascii,
              const unsigned int indent_step,
              const unsigned int current_indent = 0)
    {
        switch (val.m_type)
        {
            case value_t::object:
            {
                if (val.m_value.object->empty())
                {
                    o->write_characters("{}", 2);
                    return;
                }

                if (pretty_print)
                {
                    o->write_characters("{\n", 2);

                    const auto new_indent = current_indent + indent_step;
                    if (JSON_UNLIKELY(indent_string.size() < new_indent))
                    {
                        indent_string.resize(indent_string.size() * 2, ' ');
                    }

                    auto i = val.m_value.object->cbegin();
                    for (std::size_t cnt = 0; cnt < val.m_value.object->size() - 1; ++cnt, ++i)
                    {
                        o->write_characters(indent_string.c_str(), new_indent);
                        o->write_character('\"');
                        dump_escaped(i->first, ensure_ascii);
                        o->write_characters("\": ", 3);
                        dump(i->second, true, ensure_ascii, indent_step, new_indent);
                        o->write_characters(",\n", 2);
                    }

                    assert(i != val.m_value.object->cend());
                    assert(std::next(i) == val.m_value.object->cend());
                    o->write_characters(indent_string.c_str(), new_indent);
                    o->write_character('\"');
                    dump_escaped(i->first, ensure_ascii);
                    o->write_characters("\": ", 3);
                    dump(i->second, true, ensure_ascii, indent_step, new_indent);

                    o->write_character('\n');
                    o->write_characters(indent_string.c_str(), current_indent);
                    o->write_character('}');
                }
                else
                {
                    o->write_character('{');

                    auto i = val.m_value.object->cbegin();
                    for (std::size_t cnt = 0; cnt < val.m_value.object->size() - 1; ++cnt, ++i)
                    {
                        o->write_character('\"');
                        dump_escaped(i->first, ensure_ascii);
                        o->write_characters("\":", 2);
                        dump(i->second, false, ensure_ascii, indent_step, current_indent);
                        o->write_character(',');
                    }

                    assert(i != val.m_value.object->cend());
                    assert(std::next(i) == val.m_value.object->cend());
                    o->write_character('\"');
                    dump_escaped(i->first, ensure_ascii);
                    o->write_characters("\":", 2);
                    dump(i->second, false, ensure_ascii, indent_step, current_indent);

                    o->write_character('}');
                }

                return;
            }

            case value_t::array:
            {
                if (val.m_value.array->empty())
                {
                    o->write_characters("[]", 2);
                    return;
                }

                if (pretty_print)
                {
                    o->write_characters("[\n", 2);

                    const auto new_indent = current_indent + indent_step;
                    if (JSON_UNLIKELY(indent_string.size() < new_indent))
                    {
                        indent_string.resize(indent_string.size() * 2, ' ');
                    }

                    for (auto i = val.m_value.array->cbegin();
                            i != val.m_value.array->cend() - 1; ++i)
                    {
                        o->write_characters(indent_string.c_str(), new_indent);
                        dump(*i, true, ensure_ascii, indent_step, new_indent);
                        o->write_characters(",\n", 2);
                    }

                    assert(not val.m_value.array->empty());
                    o->write_characters(indent_string.c_str(), new_indent);
                    dump(val.m_value.array->back(), true, ensure_ascii, indent_step, new_indent);

                    o->write_character('\n');
                    o->write_characters(indent_string.c_str(), current_indent);
                    o->write_character(']');
                }
                else
                {
                    o->write_character('[');

                    for (auto i = val.m_value.array->cbegin();
                            i != val.m_value.array->cend() - 1; ++i)
                    {
                        dump(*i, false, ensure_ascii, indent_step, current_indent);
                        o->write_character(',');
                    }

                    assert(not val.m_value.array->empty());
                    dump(val.m_value.array->back(), false, ensure_ascii, indent_step, current_indent);

                    o->write_character(']');
                }

                return;
            }

            case value_t::string:
            {
                o->write_character('\"');
                dump_escaped(*val.m_value.string, ensure_ascii);
                o->write_character('\"');
                return;
            }

            case value_t::boolean:
            {
                if (val.m_value.boolean)
                {
                    o->write_characters("true", 4);
                }
                else
                {
                    o->write_characters("false", 5);
                }
                return;
            }

            case value_t::number_integer:
            {
                dump_integer(val.m_value.number_integer);
                return;
            }

            case value_t::number_unsigned:
            {
                dump_integer(val.m_value.number_unsigned);
                return;
            }

            case value_t::number_float:
            {
                dump_float(val.m_value.number_float);
                return;
            }

            case value_t::discarded:
            {
                o->write_characters("<discarded>", 11);
                return;
            }

            case value_t::null:
            {
                o->write_characters("null", 4);
                return;
            }
        }
    }

  private:
    void dump_escaped(const string_t& s, const bool ensure_ascii)
    {
        uint32_t codepoint;
        uint8_t state = UTF8_ACCEPT;
        std::size_t bytes = 0;        

        for (std::size_t i = 0; i < s.size(); ++i)
        {
            const auto byte = static_cast<uint8_t>(s[i]);

            switch (decode(state, codepoint, byte))
            {
                case UTF8_ACCEPT:        
                {
                    switch (codepoint)
                    {
                        case 0x08:  
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 'b';
                            break;
                        }

                        case 0x09:   
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 't';
                            break;
                        }

                        case 0x0A:  
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 'n';
                            break;
                        }

                        case 0x0C:  
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 'f';
                            break;
                        }

                        case 0x0D:   
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = 'r';
                            break;
                        }

                        case 0x22:   
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = '\"';
                            break;
                        }

                        case 0x5C:   
                        {
                            string_buffer[bytes++] = '\\';
                            string_buffer[bytes++] = '\\';
                            break;
                        }

                        default:
                        {
                            if ((codepoint <= 0x1F) or (ensure_ascii and (codepoint >= 0x7F)))
                            {
                                if (codepoint <= 0xFFFF)
                                {
                                    std::snprintf(string_buffer.data() + bytes, 7, "\\u%04x",
                                                  static_cast<uint16_t>(codepoint));
                                    bytes += 6;
                                }
                                else
                                {
                                    std::snprintf(string_buffer.data() + bytes, 13, "\\u%04x\\u%04x",
                                                  static_cast<uint16_t>(0xD7C0 + (codepoint >> 10)),
                                                  static_cast<uint16_t>(0xDC00 + (codepoint & 0x3FF)));
                                    bytes += 12;
                                }
                            }
                            else
                            {
                                string_buffer[bytes++] = s[i];
                            }
                            break;
                        }
                    }

                    if (string_buffer.size() - bytes < 13)
                    {
                        o->write_characters(string_buffer.data(), bytes);
                        bytes = 0;
                    }
                    break;
                }

                case UTF8_REJECT:       
                {
                    std::string sn(3, '\0');
                    snprintf(&sn[0], sn.size(), "%.2X", byte);
                    JSON_THROW(type_error::create(316, "invalid UTF-8 byte at index " + std::to_string(i) + ": 0x" + sn));
                }

                default:         
                {
                    if (not ensure_ascii)
                    {
                        string_buffer[bytes++] = s[i];
                    }
                    break;
                }
            }
        }

        if (JSON_LIKELY(state == UTF8_ACCEPT))
        {
            if (bytes > 0)
            {
                o->write_characters(string_buffer.data(), bytes);
            }
        }
        else
        {
            std::string sn(3, '\0');
            snprintf(&sn[0], sn.size(), "%.2X", static_cast<uint8_t>(s.back()));
            JSON_THROW(type_error::create(316, "incomplete UTF-8 string; last byte: 0x" + sn));
        }
    }

    template<typename NumberType, detail::enable_if_t<
                 std::is_same<NumberType, number_unsigned_t>::value or
                 std::is_same<NumberType, number_integer_t>::value,
                 int> = 0>
    void dump_integer(NumberType x)
    {
        if (x == 0)
        {
            o->write_character('0');
            return;
        }

        const bool is_negative = (x <= 0) and (x != 0);     
        std::size_t i = 0;

        while (x != 0)
        {
            assert(i < number_buffer.size() - 1);

            const auto digit = std::labs(static_cast<long>(x % 10));
            number_buffer[i++] = static_cast<char>('0' + digit);
            x /= 10;
        }

        if (is_negative)
        {
            assert(i < number_buffer.size() - 2);
            number_buffer[i++] = '-';
        }

        std::reverse(number_buffer.begin(), number_buffer.begin() + i);
        o->write_characters(number_buffer.data(), i);
    }

    void dump_float(number_float_t x)
    {
        if (not std::isfinite(x))
        {
            o->write_characters("null", 4);
            return;
        }

        static constexpr bool is_ieee_single_or_double
            = (std::numeric_limits<number_float_t>::is_iec559 and std::numeric_limits<number_float_t>::digits == 24 and std::numeric_limits<number_float_t>::max_exponent == 128) or
              (std::numeric_limits<number_float_t>::is_iec559 and std::numeric_limits<number_float_t>::digits == 53 and std::numeric_limits<number_float_t>::max_exponent == 1024);

        dump_float(x, std::integral_constant<bool, is_ieee_single_or_double>());
    }

    void dump_float(number_float_t x, std::true_type )
    {
        char* begin = number_buffer.data();
        char* end = ::nlohmann::detail::to_chars(begin, begin + number_buffer.size(), x);

        o->write_characters(begin, static_cast<size_t>(end - begin));
    }

    void dump_float(number_float_t x, std::false_type )
    {
        static constexpr auto d = std::numeric_limits<number_float_t>::max_digits10;

        std::ptrdiff_t len = snprintf(number_buffer.data(), number_buffer.size(), "%.*g", d, x);

        assert(len > 0);
        assert(static_cast<std::size_t>(len) < number_buffer.size());

        if (thousands_sep != '\0')
        {
            const auto end = std::remove(number_buffer.begin(),
                                         number_buffer.begin() + len, thousands_sep);
            std::fill(end, number_buffer.end(), '\0');
            assert((end - number_buffer.begin()) <= len);
            len = (end - number_buffer.begin());
        }

        if (decimal_point != '\0' and decimal_point != '.')
        {
            const auto dec_pos = std::find(number_buffer.begin(), number_buffer.end(), decimal_point);
            if (dec_pos != number_buffer.end())
            {
                *dec_pos = '.';
            }
        }

        o->write_characters(number_buffer.data(), static_cast<std::size_t>(len));

        const bool value_is_int_like =
            std::none_of(number_buffer.begin(), number_buffer.begin() + len + 1,
                         [](char c)
        {
            return (c == '.' or c == 'e');
        });

        if (value_is_int_like)
        {
            o->write_characters(".0", 2);
        }
    }

    static uint8_t decode(uint8_t& state, uint32_t& codep, const uint8_t byte) noexcept
    {
        static const std::array<uint8_t, 400> utf8d =
        {
            {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,  
                7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,  
                8, 8, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,  
                0xA, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x4, 0x3, 0x3,  
                0xB, 0x6, 0x6, 0x6, 0x5, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8,  
                0x0, 0x1, 0x2, 0x3, 0x5, 0x8, 0x7, 0x1, 0x1, 0x1, 0x4, 0x6, 0x1, 0x1, 0x1, 0x1,  
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1,  
                1, 2, 1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1,  
                1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, 1, 1, 1, 1,  
                1, 3, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1  
            }
        };

        const uint8_t type = utf8d[byte];

        codep = (state != UTF8_ACCEPT)
                ? (byte & 0x3fu) | (codep << 6)
                : static_cast<uint32_t>(0xff >> type) & (byte);

        state = utf8d[256u + state * 16u + type];
        return state;
    }

  private:
    output_adapter_t<char> o = nullptr;

    std::array<char, 64> number_buffer{{}};

    const std::lconv* loc = nullptr;
    const char thousands_sep = '\0';
    const char decimal_point = '\0';

    std::array<char, 512> string_buffer{{}};

    const char indent_char;
    string_t indent_string;
};
}
}


#include <initializer_list>
#include <utility>

namespace nlohmann
{
namespace detail
{
template<typename BasicJsonType>
class json_ref
{
  public:
    using value_type = BasicJsonType;

    json_ref(value_type&& value)
        : owned_value(std::move(value)), value_ref(&owned_value), is_rvalue(true)
    {}

    json_ref(const value_type& value)
        : value_ref(const_cast<value_type*>(&value)), is_rvalue(false)
    {}

    json_ref(std::initializer_list<json_ref> init)
        : owned_value(init), value_ref(&owned_value), is_rvalue(true)
    {}

    template<class... Args>
    json_ref(Args&& ... args)
        : owned_value(std::forward<Args>(args)...), value_ref(&owned_value), is_rvalue(true)
    {}

    json_ref(json_ref&&) = default;
    json_ref(const json_ref&) = delete;
    json_ref& operator=(const json_ref&) = delete;

    value_type moved_or_copied() const
    {
        if (is_rvalue)
        {
            return std::move(*value_ref);
        }
        return *value_ref;
    }

    value_type const& operator*() const
    {
        return *static_cast<value_type const*>(value_ref);
    }

    value_type const* operator->() const
    {
        return static_cast<value_type const*>(value_ref);
    }

  private:
    mutable value_type owned_value = nullptr;
    value_type* value_ref = nullptr;
    const bool is_rvalue;
};
}
}


#include <cassert>  
#include <numeric>  
#include <string>  
#include <vector>  


namespace nlohmann
{
template<typename BasicJsonType>
class json_pointer
{
    NLOHMANN_BASIC_JSON_TPL_DECLARATION
    friend class basic_json;

  public:
    explicit json_pointer(const std::string& s = "")
        : reference_tokens(split(s))
    {}

    std::string to_string() const noexcept
    {
        return std::accumulate(reference_tokens.begin(), reference_tokens.end(),
                               std::string{},
                               [](const std::string & a, const std::string & b)
        {
            return a + "/" + escape(b);
        });
    }

    operator std::string() const
    {
        return to_string();
    }

    static int array_index(const std::string& s)
    {
        std::size_t processed_chars = 0;
        const int res = std::stoi(s, &processed_chars);

        if (JSON_UNLIKELY(processed_chars != s.size()))
        {
            JSON_THROW(detail::out_of_range::create(404, "unresolved reference token '" + s + "'"));
        }

        return res;
    }

  private:
    std::string pop_back()
    {
        if (JSON_UNLIKELY(is_root()))
        {
            JSON_THROW(detail::out_of_range::create(405, "JSON pointer has no parent"));
        }

        auto last = reference_tokens.back();
        reference_tokens.pop_back();
        return last;
    }

    bool is_root() const
    {
        return reference_tokens.empty();
    }

    json_pointer top() const
    {
        if (JSON_UNLIKELY(is_root()))
        {
            JSON_THROW(detail::out_of_range::create(405, "JSON pointer has no parent"));
        }

        json_pointer result = *this;
        result.reference_tokens = {reference_tokens[0]};
        return result;
    }

    BasicJsonType& get_and_create(BasicJsonType& j) const
    {
        using size_type = typename BasicJsonType::size_type;
        auto result = &j;

        for (const auto& reference_token : reference_tokens)
        {
            switch (result->m_type)
            {
                case detail::value_t::null:
                {
                    if (reference_token == "0")
                    {
                        result = &result->operator[](0);
                    }
                    else
                    {
                        result = &result->operator[](reference_token);
                    }
                    break;
                }

                case detail::value_t::object:
                {
                    result = &result->operator[](reference_token);
                    break;
                }

                case detail::value_t::array:
                {
                    JSON_TRY
                    {
                        result = &result->operator[](static_cast<size_type>(array_index(reference_token)));
                    }
                    JSON_CATCH(std::invalid_argument&)
                    {
                        JSON_THROW(detail::parse_error::create(109, 0, "array index '" + reference_token + "' is not a number"));
                    }
                    break;
                }

                default:
                    JSON_THROW(detail::type_error::create(313, "invalid value to unflatten"));
            }
        }

        return *result;
    }

    BasicJsonType& get_unchecked(BasicJsonType* ptr) const
    {
        using size_type = typename BasicJsonType::size_type;
        for (const auto& reference_token : reference_tokens)
        {
            if (ptr->m_type == detail::value_t::null)
            {
                const bool nums =
                    std::all_of(reference_token.begin(), reference_token.end(),
                                [](const char x)
                {
                    return (x >= '0' and x <= '9');
                });

                *ptr = (nums or reference_token == "-")
                       ? detail::value_t::array
                       : detail::value_t::object;
            }

            switch (ptr->m_type)
            {
                case detail::value_t::object:
                {
                    ptr = &ptr->operator[](reference_token);
                    break;
                }

                case detail::value_t::array:
                {
                    if (JSON_UNLIKELY(reference_token.size() > 1 and reference_token[0] == '0'))
                    {
                        JSON_THROW(detail::parse_error::create(106, 0,
                                                               "array index '" + reference_token +
                                                               "' must not begin with '0'"));
                    }

                    if (reference_token == "-")
                    {
                        ptr = &ptr->operator[](ptr->m_value.array->size());
                    }
                    else
                    {
                        JSON_TRY
                        {
                            ptr = &ptr->operator[](
                                static_cast<size_type>(array_index(reference_token)));
                        }
                        JSON_CATCH(std::invalid_argument&)
                        {
                            JSON_THROW(detail::parse_error::create(109, 0, "array index '" + reference_token + "' is not a number"));
                        }
                    }
                    break;
                }

                default:
                    JSON_THROW(detail::out_of_range::create(404, "unresolved reference token '" + reference_token + "'"));
            }
        }

        return *ptr;
    }

    BasicJsonType& get_checked(BasicJsonType* ptr) const
    {
        using size_type = typename BasicJsonType::size_type;
        for (const auto& reference_token : reference_tokens)
        {
            switch (ptr->m_type)
            {
                case detail::value_t::object:
                {
                    ptr = &ptr->at(reference_token);
                    break;
                }

                case detail::value_t::array:
                {
                    if (JSON_UNLIKELY(reference_token == "-"))
                    {
                        JSON_THROW(detail::out_of_range::create(402,
                                                                "array index '-' (" + std::to_string(ptr->m_value.array->size()) +
                                                                ") is out of range"));
                    }

                    if (JSON_UNLIKELY(reference_token.size() > 1 and reference_token[0] == '0'))
                    {
                        JSON_THROW(detail::parse_error::create(106, 0,
                                                               "array index '" + reference_token +
                                                               "' must not begin with '0'"));
                    }

                    JSON_TRY
                    {
                        ptr = &ptr->at(static_cast<size_type>(array_index(reference_token)));
                    }
                    JSON_CATCH(std::invalid_argument&)
                    {
                        JSON_THROW(detail::parse_error::create(109, 0, "array index '" + reference_token + "' is not a number"));
                    }
                    break;
                }

                default:
                    JSON_THROW(detail::out_of_range::create(404, "unresolved reference token '" + reference_token + "'"));
            }
        }

        return *ptr;
    }

    const BasicJsonType& get_unchecked(const BasicJsonType* ptr) const
    {
        using size_type = typename BasicJsonType::size_type;
        for (const auto& reference_token : reference_tokens)
        {
            switch (ptr->m_type)
            {
                case detail::value_t::object:
                {
                    ptr = &ptr->operator[](reference_token);
                    break;
                }

                case detail::value_t::array:
                {
                    if (JSON_UNLIKELY(reference_token == "-"))
                    {
                        JSON_THROW(detail::out_of_range::create(402,
                                                                "array index '-' (" + std::to_string(ptr->m_value.array->size()) +
                                                                ") is out of range"));
                    }

                    if (JSON_UNLIKELY(reference_token.size() > 1 and reference_token[0] == '0'))
                    {
                        JSON_THROW(detail::parse_error::create(106, 0,
                                                               "array index '" + reference_token +
                                                               "' must not begin with '0'"));
                    }

                    JSON_TRY
                    {
                        ptr = &ptr->operator[](
                            static_cast<size_type>(array_index(reference_token)));
                    }
                    JSON_CATCH(std::invalid_argument&)
                    {
                        JSON_THROW(detail::parse_error::create(109, 0, "array index '" + reference_token + "' is not a number"));
                    }
                    break;
                }

                default:
                    JSON_THROW(detail::out_of_range::create(404, "unresolved reference token '" + reference_token + "'"));
            }
        }

        return *ptr;
    }

    const BasicJsonType& get_checked(const BasicJsonType* ptr) const
    {
        using size_type = typename BasicJsonType::size_type;
        for (const auto& reference_token : reference_tokens)
        {
            switch (ptr->m_type)
            {
                case detail::value_t::object:
                {
                    ptr = &ptr->at(reference_token);
                    break;
                }

                case detail::value_t::array:
                {
                    if (JSON_UNLIKELY(reference_token == "-"))
                    {
                        JSON_THROW(detail::out_of_range::create(402,
                                                                "array index '-' (" + std::to_string(ptr->m_value.array->size()) +
                                                                ") is out of range"));
                    }

                    if (JSON_UNLIKELY(reference_token.size() > 1 and reference_token[0] == '0'))
                    {
                        JSON_THROW(detail::parse_error::create(106, 0,
                                                               "array index '" + reference_token +
                                                               "' must not begin with '0'"));
                    }

                    JSON_TRY
                    {
                        ptr = &ptr->at(static_cast<size_type>(array_index(reference_token)));
                    }
                    JSON_CATCH(std::invalid_argument&)
                    {
                        JSON_THROW(detail::parse_error::create(109, 0, "array index '" + reference_token + "' is not a number"));
                    }
                    break;
                }

                default:
                    JSON_THROW(detail::out_of_range::create(404, "unresolved reference token '" + reference_token + "'"));
            }
        }

        return *ptr;
    }

    static std::vector<std::string> split(const std::string& reference_string)
    {
        std::vector<std::string> result;

        if (reference_string.empty())
        {
            return result;
        }

        if (JSON_UNLIKELY(reference_string[0] != '/'))
        {
            JSON_THROW(detail::parse_error::create(107, 1,
                                                   "JSON pointer must be empty or begin with '/' - was: '" +
                                                   reference_string + "'"));
        }

        for (
            std::size_t slash = reference_string.find_first_of('/', 1),
            start = 1;
            start != 0;
            start = slash + 1,
            slash = reference_string.find_first_of('/', start))
        {
            auto reference_token = reference_string.substr(start, slash - start);

            for (std::size_t pos = reference_token.find_first_of('~');
                    pos != std::string::npos;
                    pos = reference_token.find_first_of('~', pos + 1))
            {
                assert(reference_token[pos] == '~');

                if (JSON_UNLIKELY(pos == reference_token.size() - 1 or
                                  (reference_token[pos + 1] != '0' and
                                   reference_token[pos + 1] != '1')))
                {
                    JSON_THROW(detail::parse_error::create(108, 0, "escape character '~' must be followed with '0' or '1'"));
                }
            }

            unescape(reference_token);
            result.push_back(reference_token);
        }

        return result;
    }

    static void replace_substring(std::string& s, const std::string& f,
                                  const std::string& t)
    {
        assert(not f.empty());
        for (auto pos = s.find(f);                     
                pos != std::string::npos;              
                s.replace(pos, f.size(), t),          
                pos = s.find(f, pos + t.size()))       
        {}
    }

    static std::string escape(std::string s)
    {
        replace_substring(s, "~", "~0");
        replace_substring(s, "/", "~1");
        return s;
    }

    static void unescape(std::string& s)
    {
        replace_substring(s, "~1", "/");
        replace_substring(s, "~0", "~");
    }

    static void flatten(const std::string& reference_string,
                        const BasicJsonType& value,
                        BasicJsonType& result)
    {
        switch (value.m_type)
        {
            case detail::value_t::array:
            {
                if (value.m_value.array->empty())
                {
                    result[reference_string] = nullptr;
                }
                else
                {
                    for (std::size_t i = 0; i < value.m_value.array->size(); ++i)
                    {
                        flatten(reference_string + "/" + std::to_string(i),
                                value.m_value.array->operator[](i), result);
                    }
                }
                break;
            }

            case detail::value_t::object:
            {
                if (value.m_value.object->empty())
                {
                    result[reference_string] = nullptr;
                }
                else
                {
                    for (const auto& element : *value.m_value.object)
                    {
                        flatten(reference_string + "/" + escape(element.first), element.second, result);
                    }
                }
                break;
            }

            default:
            {
                result[reference_string] = value;
                break;
            }
        }
    }

    static BasicJsonType
    unflatten(const BasicJsonType& value)
    {
        if (JSON_UNLIKELY(not value.is_object()))
        {
            JSON_THROW(detail::type_error::create(314, "only objects can be unflattened"));
        }

        BasicJsonType result;

        for (const auto& element : *value.m_value.object)
        {
            if (JSON_UNLIKELY(not element.second.is_primitive()))
            {
                JSON_THROW(detail::type_error::create(315, "values in object must be primitive"));
            }

            json_pointer(element.first).get_and_create(result) = element.second;
        }

        return result;
    }

    friend bool operator==(json_pointer const& lhs,
                           json_pointer const& rhs) noexcept
    {
        return (lhs.reference_tokens == rhs.reference_tokens);
    }

    friend bool operator!=(json_pointer const& lhs,
                           json_pointer const& rhs) noexcept
    {
        return not (lhs == rhs);
    }

    std::vector<std::string> reference_tokens;
};
}


#include <utility>


namespace nlohmann
{
template<typename, typename>
struct adl_serializer
{
    template<typename BasicJsonType, typename ValueType>
    static void from_json(BasicJsonType&& j, ValueType& val) noexcept(
        noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), val)))
    {
        ::nlohmann::from_json(std::forward<BasicJsonType>(j), val);
    }

    template<typename BasicJsonType, typename ValueType>
    static void to_json(BasicJsonType& j, ValueType&& val) noexcept(
        noexcept(::nlohmann::to_json(j, std::forward<ValueType>(val))))
    {
        ::nlohmann::to_json(j, std::forward<ValueType>(val));
    }
};
}
namespace nlohmann
{
NLOHMANN_BASIC_JSON_TPL_DECLARATION
class basic_json
{
  private:
    template<detail::value_t> friend struct detail::external_constructor;
    friend ::nlohmann::json_pointer<basic_json>;
    friend ::nlohmann::detail::parser<basic_json>;
    friend ::nlohmann::detail::serializer<basic_json>;
    template<typename BasicJsonType>
    friend class ::nlohmann::detail::iter_impl;
    template<typename BasicJsonType, typename CharType>
    friend class ::nlohmann::detail::binary_writer;
    template<typename BasicJsonType, typename SAX>
    friend class ::nlohmann::detail::binary_reader;
    template<typename BasicJsonType>
    friend class ::nlohmann::detail::json_sax_dom_parser;
    template<typename BasicJsonType>
    friend class ::nlohmann::detail::json_sax_dom_callback_parser;

    using basic_json_t = NLOHMANN_BASIC_JSON_TPL;

    using lexer = ::nlohmann::detail::lexer<basic_json>;
    using parser = ::nlohmann::detail::parser<basic_json>;

    using primitive_iterator_t = ::nlohmann::detail::primitive_iterator_t;
    template<typename BasicJsonType>
    using internal_iterator = ::nlohmann::detail::internal_iterator<BasicJsonType>;
    template<typename BasicJsonType>
    using iter_impl = ::nlohmann::detail::iter_impl<BasicJsonType>;
    template<typename Iterator>
    using iteration_proxy = ::nlohmann::detail::iteration_proxy<Iterator>;
    template<typename Base> using json_reverse_iterator = ::nlohmann::detail::json_reverse_iterator<Base>;

    template<typename CharType>
    using output_adapter_t = ::nlohmann::detail::output_adapter_t<CharType>;

    using binary_reader = ::nlohmann::detail::binary_reader<basic_json>;
    template<typename CharType> using binary_writer = ::nlohmann::detail::binary_writer<basic_json, CharType>;

    using serializer = ::nlohmann::detail::serializer<basic_json>;

  public:
    using value_t = detail::value_t;
    using json_pointer = ::nlohmann::json_pointer<basic_json>;
    template<typename T, typename SFINAE>
    using json_serializer = JSONSerializer<T, SFINAE>;
    using initializer_list_t = std::initializer_list<detail::json_ref<basic_json>>;

    using input_format_t = detail::input_format_t;
    using json_sax_t = json_sax<basic_json>;

    using exception = detail::exception;
    using parse_error = detail::parse_error;
    using invalid_iterator = detail::invalid_iterator;
    using type_error = detail::type_error;
    using out_of_range = detail::out_of_range;
    using other_error = detail::other_error;

    using value_type = basic_json;

    using reference = value_type&;
    using const_reference = const value_type&;

    using difference_type = std::ptrdiff_t;
    using size_type = std::size_t;

    using allocator_type = AllocatorType<basic_json>;

    using pointer = typename std::allocator_traits<allocator_type>::pointer;
    using const_pointer = typename std::allocator_traits<allocator_type>::const_pointer;

    using iterator = iter_impl<basic_json>;
    using const_iterator = iter_impl<const basic_json>;
    using reverse_iterator = json_reverse_iterator<typename basic_json::iterator>;
    using const_reverse_iterator = json_reverse_iterator<typename basic_json::const_iterator>;

    static allocator_type get_allocator()
    {
        return allocator_type();
    }
    static basic_json meta()
    {
        basic_json result;

        result["copyright"] = "(C) 2013-2017 Niels Lohmann";
        result["name"] = "JSON for Modern C++";
        result["url"] = "https://github.com/nlohmann/json";
        result["version"]["string"] =
            std::to_string(NLOHMANN_JSON_VERSION_MAJOR) + "." +
            std::to_string(NLOHMANN_JSON_VERSION_MINOR) + "." +
            std::to_string(NLOHMANN_JSON_VERSION_PATCH);
        result["version"]["major"] = NLOHMANN_JSON_VERSION_MAJOR;
        result["version"]["minor"] = NLOHMANN_JSON_VERSION_MINOR;
        result["version"]["patch"] = NLOHMANN_JSON_VERSION_PATCH;

#ifdef _WIN32
        result["platform"] = "win32";
#elif defined __linux__
        result["platform"] = "linux";
#elif defined __APPLE__
        result["platform"] = "apple";
#elif defined __unix__
        result["platform"] = "unix";
#else
        result["platform"] = "unknown";
#endif

#if defined(__ICC) || defined(__INTEL_COMPILER)
        result["compiler"] = {{"family", "icc"}, {"version", __INTEL_COMPILER}};
#elif defined(__clang__)
        result["compiler"] = {{"family", "clang"}, {"version", __clang_version__}};
#elif defined(__GNUC__) || defined(__GNUG__)
        result["compiler"] = {{"family", "gcc"}, {"version", std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__) + "." + std::to_string(__GNUC_PATCHLEVEL__)}};
#elif defined(__HP_cc) || defined(__HP_aCC)
        result["compiler"] = "hp"
#elif defined(__IBMCPP__)
        result["compiler"] = {{"family", "ilecpp"}, {"version", __IBMCPP__}};
#elif defined(_MSC_VER)
        result["compiler"] = {{"family", "msvc"}, {"version", _MSC_VER}};
#elif defined(__PGI)
        result["compiler"] = {{"family", "pgcpp"}, {"version", __PGI}};
#elif defined(__SUNPRO_CC)
        result["compiler"] = {{"family", "sunpro"}, {"version", __SUNPRO_CC}};
#else
        result["compiler"] = {{"family", "unknown"}, {"version", "unknown"}};
#endif

#ifdef __cplusplus
        result["compiler"]["c++"] = std::to_string(__cplusplus);
#else
        result["compiler"]["c++"] = "unknown";
#endif
        return result;
    }

#if defined(JSON_HAS_CPP_14)
    using object_comparator_t = std::less<>;
#else
    using object_comparator_t = std::less<StringType>;
#endif

    using object_t = ObjectType<StringType,
          basic_json,
          object_comparator_t,
          AllocatorType<std::pair<const StringType,
          basic_json>>>;

    using array_t = ArrayType<basic_json, AllocatorType<basic_json>>;

    using string_t = StringType;

    using boolean_t = BooleanType;

    using number_integer_t = NumberIntegerType;

    using number_unsigned_t = NumberUnsignedType;

    using number_float_t = NumberFloatType;

  private:

    template<typename T, typename... Args>
    static T* create(Args&& ... args)
    {
        AllocatorType<T> alloc;
        using AllocatorTraits = std::allocator_traits<AllocatorType<T>>;

        auto deleter = [&](T * object)
        {
            AllocatorTraits::deallocate(alloc, object, 1);
        };
        std::unique_ptr<T, decltype(deleter)> object(AllocatorTraits::allocate(alloc, 1), deleter);
        AllocatorTraits::construct(alloc, object.get(), std::forward<Args>(args)...);
        assert(object != nullptr);
        return object.release();
    }
    union json_value
    {
        object_t* object;
        array_t* array;
        string_t* string;
        boolean_t boolean;
        number_integer_t number_integer;
        number_unsigned_t number_unsigned;
        number_float_t number_float;

        json_value() = default;
        json_value(boolean_t v) noexcept : boolean(v) {}
        json_value(number_integer_t v) noexcept : number_integer(v) {}
        json_value(number_unsigned_t v) noexcept : number_unsigned(v) {}
        json_value(number_float_t v) noexcept : number_float(v) {}
        json_value(value_t t)
        {
            switch (t)
            {
                case value_t::object:
                {
                    object = create<object_t>();
                    break;
                }

                case value_t::array:
                {
                    array = create<array_t>();
                    break;
                }

                case value_t::string:
                {
                    string = create<string_t>("");
                    break;
                }

                case value_t::boolean:
                {
                    boolean = boolean_t(false);
                    break;
                }

                case value_t::number_integer:
                {
                    number_integer = number_integer_t(0);
                    break;
                }

                case value_t::number_unsigned:
                {
                    number_unsigned = number_unsigned_t(0);
                    break;
                }

                case value_t::number_float:
                {
                    number_float = number_float_t(0.0);
                    break;
                }

                case value_t::null:
                {
                    object = nullptr;      
                    break;
                }

                default:
                {
                    object = nullptr;      
                    if (JSON_UNLIKELY(t == value_t::null))
                    {
                        JSON_THROW(other_error::create(500, "961c151d2e87f2686a955a9be24d316f1362bf21 3.2.0"));  
                    }
                    break;
                }
            }
        }

        json_value(const string_t& value)
        {
            string = create<string_t>(value);
        }

        json_value(string_t&& value)
        {
            string = create<string_t>(std::move(value));
        }

        json_value(const object_t& value)
        {
            object = create<object_t>(value);
        }

        json_value(object_t&& value)
        {
            object = create<object_t>(std::move(value));
        }

        json_value(const array_t& value)
        {
            array = create<array_t>(value);
        }

        json_value(array_t&& value)
        {
            array = create<array_t>(std::move(value));
        }

        void destroy(value_t t) noexcept
        {
            switch (t)
            {
                case value_t::object:
                {
                    AllocatorType<object_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, object);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, object, 1);
                    break;
                }

                case value_t::array:
                {
                    AllocatorType<array_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, array);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, array, 1);
                    break;
                }

                case value_t::string:
                {
                    AllocatorType<string_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, string);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, string, 1);
                    break;
                }

                default:
                {
                    break;
                }
            }
        }
    };

    void assert_invariant() const noexcept
    {
        assert(m_type != value_t::object or m_value.object != nullptr);
        assert(m_type != value_t::array or m_value.array != nullptr);
        assert(m_type != value_t::string or m_value.string != nullptr);
    }

  public:
    using parse_event_t = typename parser::parse_event_t;

    using parser_callback_t = typename parser::parser_callback_t;

    basic_json(const value_t v)
        : m_type(v), m_value(v)
    {
        assert_invariant();
    }

    basic_json(std::nullptr_t = nullptr) noexcept
        : basic_json(value_t::null)
    {
        assert_invariant();
    }

    template <typename CompatibleType,
              typename U = detail::uncvref_t<CompatibleType>,
              detail::enable_if_t<
                  detail::is_compatible_type<basic_json_t, U>::value, int> = 0>
    basic_json(CompatibleType && val) noexcept(noexcept(
                JSONSerializer<U>::to_json(std::declval<basic_json_t&>(),
                                           std::forward<CompatibleType>(val))))
    {
        JSONSerializer<U>::to_json(*this, std::forward<CompatibleType>(val));
        assert_invariant();
    }

    template <typename BasicJsonType,
              detail::enable_if_t<
                  detail::is_basic_json<BasicJsonType>::value and not std::is_same<basic_json, BasicJsonType>::value, int> = 0>
    basic_json(const BasicJsonType& val)
    {
        using other_boolean_t = typename BasicJsonType::boolean_t;
        using other_number_float_t = typename BasicJsonType::number_float_t;
        using other_number_integer_t = typename BasicJsonType::number_integer_t;
        using other_number_unsigned_t = typename BasicJsonType::number_unsigned_t;
        using other_string_t = typename BasicJsonType::string_t;
        using other_object_t = typename BasicJsonType::object_t;
        using other_array_t = typename BasicJsonType::array_t;

        switch (val.type())
        {
            case value_t::boolean:
                JSONSerializer<other_boolean_t>::to_json(*this, val.template get<other_boolean_t>());
                break;
            case value_t::number_float:
                JSONSerializer<other_number_float_t>::to_json(*this, val.template get<other_number_float_t>());
                break;
            case value_t::number_integer:
                JSONSerializer<other_number_integer_t>::to_json(*this, val.template get<other_number_integer_t>());
                break;
            case value_t::number_unsigned:
                JSONSerializer<other_number_unsigned_t>::to_json(*this, val.template get<other_number_unsigned_t>());
                break;
            case value_t::string:
                JSONSerializer<other_string_t>::to_json(*this, val.template get_ref<const other_string_t&>());
                break;
            case value_t::object:
                JSONSerializer<other_object_t>::to_json(*this, val.template get_ref<const other_object_t&>());
                break;
            case value_t::array:
                JSONSerializer<other_array_t>::to_json(*this, val.template get_ref<const other_array_t&>());
                break;
            case value_t::null:
                *this = nullptr;
                break;
            case value_t::discarded:
                m_type = value_t::discarded;
                break;
        }
        assert_invariant();
    }

    basic_json(initializer_list_t init,
               bool type_deduction = true,
               value_t manual_type = value_t::array)
    {
        bool is_an_object = std::all_of(init.begin(), init.end(),
                                        [](const detail::json_ref<basic_json>& element_ref)
        {
            return (element_ref->is_array() and element_ref->size() == 2 and (*element_ref)[0].is_string());
        });

        if (not type_deduction)
        {
            if (manual_type == value_t::array)
            {
                is_an_object = false;
            }

            if (JSON_UNLIKELY(manual_type == value_t::object and not is_an_object))
            {
                JSON_THROW(type_error::create(301, "cannot create object from initializer list"));
            }
        }

        if (is_an_object)
        {
            m_type = value_t::object;
            m_value = value_t::object;

            std::for_each(init.begin(), init.end(), [this](const detail::json_ref<basic_json>& element_ref)
            {
                auto element = element_ref.moved_or_copied();
                m_value.object->emplace(
                    std::move(*((*element.m_value.array)[0].m_value.string)),
                    std::move((*element.m_value.array)[1]));
            });
        }
        else
        {
            m_type = value_t::array;
            m_value.array = create<array_t>(init.begin(), init.end());
        }

        assert_invariant();
    }

    static basic_json array(initializer_list_t init = {})
    {
        return basic_json(init, false, value_t::array);
    }

    static basic_json object(initializer_list_t init = {})
    {
        return basic_json(init, false, value_t::object);
    }

    basic_json(size_type cnt, const basic_json& val)
        : m_type(value_t::array)
    {
        m_value.array = create<array_t>(cnt, val);
        assert_invariant();
    }

    template<class InputIT, typename std::enable_if<
                 std::is_same<InputIT, typename basic_json_t::iterator>::value or
                 std::is_same<InputIT, typename basic_json_t::const_iterator>::value, int>::type = 0>
    basic_json(InputIT first, InputIT last)
    {
        assert(first.m_object != nullptr);
        assert(last.m_object != nullptr);

        if (JSON_UNLIKELY(first.m_object != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(201, "iterators are not compatible"));
        }

        m_type = first.m_object->m_type;

        switch (m_type)
        {
            case value_t::boolean:
            case value_t::number_float:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::string:
            {
                if (JSON_UNLIKELY(not first.m_it.primitive_iterator.is_begin()
                                  or not last.m_it.primitive_iterator.is_end()))
                {
                    JSON_THROW(invalid_iterator::create(204, "iterators out of range"));
                }
                break;
            }

            default:
                break;
        }

        switch (m_type)
        {
            case value_t::number_integer:
            {
                m_value.number_integer = first.m_object->m_value.number_integer;
                break;
            }

            case value_t::number_unsigned:
            {
                m_value.number_unsigned = first.m_object->m_value.number_unsigned;
                break;
            }

            case value_t::number_float:
            {
                m_value.number_float = first.m_object->m_value.number_float;
                break;
            }

            case value_t::boolean:
            {
                m_value.boolean = first.m_object->m_value.boolean;
                break;
            }

            case value_t::string:
            {
                m_value = *first.m_object->m_value.string;
                break;
            }

            case value_t::object:
            {
                m_value.object = create<object_t>(first.m_it.object_iterator,
                                                  last.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                m_value.array = create<array_t>(first.m_it.array_iterator,
                                                last.m_it.array_iterator);
                break;
            }

            default:
                JSON_THROW(invalid_iterator::create(206, "cannot construct with iterators from " +
                                                    std::string(first.m_object->type_name())));
        }

        assert_invariant();
    }


    basic_json(const detail::json_ref<basic_json>& ref)
        : basic_json(ref.moved_or_copied())
    {}

    basic_json(const basic_json& other)
        : m_type(other.m_type)
    {
        other.assert_invariant();

        switch (m_type)
        {
            case value_t::object:
            {
                m_value = *other.m_value.object;
                break;
            }

            case value_t::array:
            {
                m_value = *other.m_value.array;
                break;
            }

            case value_t::string:
            {
                m_value = *other.m_value.string;
                break;
            }

            case value_t::boolean:
            {
                m_value = other.m_value.boolean;
                break;
            }

            case value_t::number_integer:
            {
                m_value = other.m_value.number_integer;
                break;
            }

            case value_t::number_unsigned:
            {
                m_value = other.m_value.number_unsigned;
                break;
            }

            case value_t::number_float:
            {
                m_value = other.m_value.number_float;
                break;
            }

            default:
                break;
        }

        assert_invariant();
    }

    basic_json(basic_json&& other) noexcept
        : m_type(std::move(other.m_type)),
          m_value(std::move(other.m_value))
    {
        other.assert_invariant();

        other.m_type = value_t::null;
        other.m_value = {};

        assert_invariant();
    }

    reference& operator=(basic_json other) noexcept (
        std::is_nothrow_move_constructible<value_t>::value and
        std::is_nothrow_move_assignable<value_t>::value and
        std::is_nothrow_move_constructible<json_value>::value and
        std::is_nothrow_move_assignable<json_value>::value
    )
    {
        other.assert_invariant();

        using std::swap;
        swap(m_type, other.m_type);
        swap(m_value, other.m_value);

        assert_invariant();
        return *this;
    }

    ~basic_json() noexcept
    {
        assert_invariant();
        m_value.destroy(m_type);
    }

  public:
    string_t dump(const int indent = -1, const char indent_char = ' ',
                  const bool ensure_ascii = false) const
    {
        string_t result;
        serializer s(detail::output_adapter<char, string_t>(result), indent_char);

        if (indent >= 0)
        {
            s.dump(*this, true, ensure_ascii, static_cast<unsigned int>(indent));
        }
        else
        {
            s.dump(*this, false, ensure_ascii, 0);
        }

        return result;
    }

    constexpr value_t type() const noexcept
    {
        return m_type;
    }

    constexpr bool is_primitive() const noexcept
    {
        return is_null() or is_string() or is_boolean() or is_number();
    }

    constexpr bool is_structured() const noexcept
    {
        return is_array() or is_object();
    }

    constexpr bool is_null() const noexcept
    {
        return (m_type == value_t::null);
    }

    constexpr bool is_boolean() const noexcept
    {
        return (m_type == value_t::boolean);
    }

    constexpr bool is_number() const noexcept
    {
        return is_number_integer() or is_number_float();
    }

    constexpr bool is_number_integer() const noexcept
    {
        return (m_type == value_t::number_integer or m_type == value_t::number_unsigned);
    }

    constexpr bool is_number_unsigned() const noexcept
    {
        return (m_type == value_t::number_unsigned);
    }

    constexpr bool is_number_float() const noexcept
    {
        return (m_type == value_t::number_float);
    }

    constexpr bool is_object() const noexcept
    {
        return (m_type == value_t::object);
    }

    constexpr bool is_array() const noexcept
    {
        return (m_type == value_t::array);
    }

    constexpr bool is_string() const noexcept
    {
        return (m_type == value_t::string);
    }

    constexpr bool is_discarded() const noexcept
    {
        return (m_type == value_t::discarded);
    }

    constexpr operator value_t() const noexcept
    {
        return m_type;
    }

  private:
    boolean_t get_impl(boolean_t* ) const
    {
        if (JSON_LIKELY(is_boolean()))
        {
            return m_value.boolean;
        }

        JSON_THROW(type_error::create(302, "type must be boolean, but is " + std::string(type_name())));
    }

    object_t* get_impl_ptr(object_t* ) noexcept
    {
        return is_object() ? m_value.object : nullptr;
    }

    constexpr const object_t* get_impl_ptr(const object_t* ) const noexcept
    {
        return is_object() ? m_value.object : nullptr;
    }

    array_t* get_impl_ptr(array_t* ) noexcept
    {
        return is_array() ? m_value.array : nullptr;
    }

    constexpr const array_t* get_impl_ptr(const array_t* ) const noexcept
    {
        return is_array() ? m_value.array : nullptr;
    }

    string_t* get_impl_ptr(string_t* ) noexcept
    {
        return is_string() ? m_value.string : nullptr;
    }

    constexpr const string_t* get_impl_ptr(const string_t* ) const noexcept
    {
        return is_string() ? m_value.string : nullptr;
    }

    boolean_t* get_impl_ptr(boolean_t* ) noexcept
    {
        return is_boolean() ? &m_value.boolean : nullptr;
    }

    constexpr const boolean_t* get_impl_ptr(const boolean_t* ) const noexcept
    {
        return is_boolean() ? &m_value.boolean : nullptr;
    }

    number_integer_t* get_impl_ptr(number_integer_t* ) noexcept
    {
        return is_number_integer() ? &m_value.number_integer : nullptr;
    }

    constexpr const number_integer_t* get_impl_ptr(const number_integer_t* ) const noexcept
    {
        return is_number_integer() ? &m_value.number_integer : nullptr;
    }

    number_unsigned_t* get_impl_ptr(number_unsigned_t* ) noexcept
    {
        return is_number_unsigned() ? &m_value.number_unsigned : nullptr;
    }

    constexpr const number_unsigned_t* get_impl_ptr(const number_unsigned_t* ) const noexcept
    {
        return is_number_unsigned() ? &m_value.number_unsigned : nullptr;
    }

    number_float_t* get_impl_ptr(number_float_t* ) noexcept
    {
        return is_number_float() ? &m_value.number_float : nullptr;
    }

    constexpr const number_float_t* get_impl_ptr(const number_float_t* ) const noexcept
    {
        return is_number_float() ? &m_value.number_float : nullptr;
    }

    template<typename ReferenceType, typename ThisType>
    static ReferenceType get_ref_impl(ThisType& obj)
    {
        auto ptr = obj.template get_ptr<typename std::add_pointer<ReferenceType>::type>();

        if (JSON_LIKELY(ptr != nullptr))
        {
            return *ptr;
        }

        JSON_THROW(type_error::create(303, "incompatible ReferenceType for get_ref, actual type is " + std::string(obj.type_name())));
    }

  public:
    template<typename BasicJsonType, detail::enable_if_t<
                 std::is_same<typename std::remove_const<BasicJsonType>::type, basic_json_t>::value,
                 int> = 0>
    basic_json get() const
    {
        return *this;
    }

    template<typename BasicJsonType, detail::enable_if_t<
                 not std::is_same<BasicJsonType, basic_json>::value and
                 detail::is_basic_json<BasicJsonType>::value, int> = 0>
    BasicJsonType get() const
    {
        return *this;
    }

    template<typename ValueTypeCV, typename ValueType = detail::uncvref_t<ValueTypeCV>,
             detail::enable_if_t <
                 not detail::is_basic_json<ValueType>::value and
                 detail::has_from_json<basic_json_t, ValueType>::value and
                 not detail::has_non_default_from_json<basic_json_t, ValueType>::value,
                 int> = 0>
    ValueType get() const noexcept(noexcept(
                                       JSONSerializer<ValueType>::from_json(std::declval<const basic_json_t&>(), std::declval<ValueType&>())))
    {
        static_assert(not std::is_reference<ValueTypeCV>::value,
                      "get() cannot be used with reference types, you might want to use get_ref()");
        static_assert(std::is_default_constructible<ValueType>::value,
                      "types must be DefaultConstructible when used with get()");

        ValueType ret;
        JSONSerializer<ValueType>::from_json(*this, ret);
        return ret;
    }

    template<typename ValueTypeCV, typename ValueType = detail::uncvref_t<ValueTypeCV>,
             detail::enable_if_t<not std::is_same<basic_json_t, ValueType>::value and
                                 detail::has_non_default_from_json<basic_json_t, ValueType>::value,
                                 int> = 0>
    ValueType get() const noexcept(noexcept(
                                       JSONSerializer<ValueTypeCV>::from_json(std::declval<const basic_json_t&>())))
    {
        static_assert(not std::is_reference<ValueTypeCV>::value,
                      "get() cannot be used with reference types, you might want to use get_ref()");
        return JSONSerializer<ValueTypeCV>::from_json(*this);
    }

    template<typename PointerType, typename std::enable_if<
                 std::is_pointer<PointerType>::value, int>::type = 0>
    PointerType get() noexcept
    {
        return get_ptr<PointerType>();
    }

    template<typename PointerType, typename std::enable_if<
                 std::is_pointer<PointerType>::value, int>::type = 0>
    constexpr const PointerType get() const noexcept
    {
        return get_ptr<PointerType>();
    }

    template<typename PointerType, typename std::enable_if<
                 std::is_pointer<PointerType>::value, int>::type = 0>
    PointerType get_ptr() noexcept
    {
        using pointee_t = typename std::remove_const<typename
                          std::remove_pointer<typename
                          std::remove_const<PointerType>::type>::type>::type;
        static_assert(
            std::is_same<object_t, pointee_t>::value
            or std::is_same<array_t, pointee_t>::value
            or std::is_same<string_t, pointee_t>::value
            or std::is_same<boolean_t, pointee_t>::value
            or std::is_same<number_integer_t, pointee_t>::value
            or std::is_same<number_unsigned_t, pointee_t>::value
            or std::is_same<number_float_t, pointee_t>::value
            , "incompatible pointer type");

        return get_impl_ptr(static_cast<PointerType>(nullptr));
    }

    template<typename PointerType, typename std::enable_if<
                 std::is_pointer<PointerType>::value and
                 std::is_const<typename std::remove_pointer<PointerType>::type>::value, int>::type = 0>
    constexpr const PointerType get_ptr() const noexcept
    {
        using pointee_t = typename std::remove_const<typename
                          std::remove_pointer<typename
                          std::remove_const<PointerType>::type>::type>::type;
        static_assert(
            std::is_same<object_t, pointee_t>::value
            or std::is_same<array_t, pointee_t>::value
            or std::is_same<string_t, pointee_t>::value
            or std::is_same<boolean_t, pointee_t>::value
            or std::is_same<number_integer_t, pointee_t>::value
            or std::is_same<number_unsigned_t, pointee_t>::value
            or std::is_same<number_float_t, pointee_t>::value
            , "incompatible pointer type");

        return get_impl_ptr(static_cast<PointerType>(nullptr));
    }

    template<typename ReferenceType, typename std::enable_if<
                 std::is_reference<ReferenceType>::value, int>::type = 0>
    ReferenceType get_ref()
    {
        return get_ref_impl<ReferenceType>(*this);
    }

    template<typename ReferenceType, typename std::enable_if<
                 std::is_reference<ReferenceType>::value and
                 std::is_const<typename std::remove_reference<ReferenceType>::type>::value, int>::type = 0>
    ReferenceType get_ref() const
    {
        return get_ref_impl<ReferenceType>(*this);
    }

    template < typename ValueType, typename std::enable_if <
                   not std::is_pointer<ValueType>::value and
                   not std::is_same<ValueType, detail::json_ref<basic_json>>::value and
                   not std::is_same<ValueType, typename string_t::value_type>::value and
                   not detail::is_basic_json<ValueType>::value
#ifndef _MSC_VER          
                   and not std::is_same<ValueType, std::initializer_list<typename string_t::value_type>>::value
#if defined(JSON_HAS_CPP_17) && defined(_MSC_VER) and _MSC_VER <= 1914
                   and not std::is_same<ValueType, typename std::string_view>::value
#endif
#endif
                   , int >::type = 0 >
    operator ValueType() const
    {
        return get<ValueType>();
    }


    reference at(size_type idx)
    {
        if (JSON_LIKELY(is_array()))
        {
            JSON_TRY
            {
                return m_value.array->at(idx);
            }
            JSON_CATCH (std::out_of_range&)
            {
                JSON_THROW(out_of_range::create(401, "array index " + std::to_string(idx) + " is out of range"));
            }
        }
        else
        {
            JSON_THROW(type_error::create(304, "cannot use at() with " + std::string(type_name())));
        }
    }

    const_reference at(size_type idx) const
    {
        if (JSON_LIKELY(is_array()))
        {
            JSON_TRY
            {
                return m_value.array->at(idx);
            }
            JSON_CATCH (std::out_of_range&)
            {
                JSON_THROW(out_of_range::create(401, "array index " + std::to_string(idx) + " is out of range"));
            }
        }
        else
        {
            JSON_THROW(type_error::create(304, "cannot use at() with " + std::string(type_name())));
        }
    }

    reference at(const typename object_t::key_type& key)
    {
        if (JSON_LIKELY(is_object()))
        {
            JSON_TRY
            {
                return m_value.object->at(key);
            }
            JSON_CATCH (std::out_of_range&)
            {
                JSON_THROW(out_of_range::create(403, "key '" + key + "' not found"));
            }
        }
        else
        {
            JSON_THROW(type_error::create(304, "cannot use at() with " + std::string(type_name())));
        }
    }

    const_reference at(const typename object_t::key_type& key) const
    {
        if (JSON_LIKELY(is_object()))
        {
            JSON_TRY
            {
                return m_value.object->at(key);
            }
            JSON_CATCH (std::out_of_range&)
            {
                JSON_THROW(out_of_range::create(403, "key '" + key + "' not found"));
            }
        }
        else
        {
            JSON_THROW(type_error::create(304, "cannot use at() with " + std::string(type_name())));
        }
    }

    reference operator[](size_type idx)
    {
        if (is_null())
        {
            m_type = value_t::array;
            m_value.array = create<array_t>();
            assert_invariant();
        }

        if (JSON_LIKELY(is_array()))
        {
            if (idx >= m_value.array->size())
            {
                m_value.array->insert(m_value.array->end(),
                                      idx - m_value.array->size() + 1,
                                      basic_json());
            }

            return m_value.array->operator[](idx);
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with " + std::string(type_name())));
    }

    const_reference operator[](size_type idx) const
    {
        if (JSON_LIKELY(is_array()))
        {
            return m_value.array->operator[](idx);
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with " + std::string(type_name())));
    }

    reference operator[](const typename object_t::key_type& key)
    {
        if (is_null())
        {
            m_type = value_t::object;
            m_value.object = create<object_t>();
            assert_invariant();
        }

        if (JSON_LIKELY(is_object()))
        {
            return m_value.object->operator[](key);
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with " + std::string(type_name())));
    }

    const_reference operator[](const typename object_t::key_type& key) const
    {
        if (JSON_LIKELY(is_object()))
        {
            assert(m_value.object->find(key) != m_value.object->end());
            return m_value.object->find(key)->second;
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with " + std::string(type_name())));
    }

    template<typename T>
    reference operator[](T* key)
    {
        if (is_null())
        {
            m_type = value_t::object;
            m_value = value_t::object;
            assert_invariant();
        }

        if (JSON_LIKELY(is_object()))
        {
            return m_value.object->operator[](key);
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with " + std::string(type_name())));
    }

    template<typename T>
    const_reference operator[](T* key) const
    {
        if (JSON_LIKELY(is_object()))
        {
            assert(m_value.object->find(key) != m_value.object->end());
            return m_value.object->find(key)->second;
        }

        JSON_THROW(type_error::create(305, "cannot use operator[] with " + std::string(type_name())));
    }

    template<class ValueType, typename std::enable_if<
                 std::is_convertible<basic_json_t, ValueType>::value, int>::type = 0>
    ValueType value(const typename object_t::key_type& key, const ValueType& default_value) const
    {
        if (JSON_LIKELY(is_object()))
        {
            const auto it = find(key);
            if (it != end())
            {
                return *it;
            }

            return default_value;
        }

        JSON_THROW(type_error::create(306, "cannot use value() with " + std::string(type_name())));
    }

    string_t value(const typename object_t::key_type& key, const char* default_value) const
    {
        return value(key, string_t(default_value));
    }

    template<class ValueType, typename std::enable_if<
                 std::is_convertible<basic_json_t, ValueType>::value, int>::type = 0>
    ValueType value(const json_pointer& ptr, const ValueType& default_value) const
    {
        if (JSON_LIKELY(is_object()))
        {
            JSON_TRY
            {
                return ptr.get_checked(this);
            }
            JSON_INTERNAL_CATCH (out_of_range&)
            {
                return default_value;
            }
        }

        JSON_THROW(type_error::create(306, "cannot use value() with " + std::string(type_name())));
    }

    string_t value(const json_pointer& ptr, const char* default_value) const
    {
        return value(ptr, string_t(default_value));
    }

    reference front()
    {
        return *begin();
    }

    const_reference front() const
    {
        return *cbegin();
    }

    reference back()
    {
        auto tmp = end();
        --tmp;
        return *tmp;
    }

    const_reference back() const
    {
        auto tmp = cend();
        --tmp;
        return *tmp;
    }

    template<class IteratorType, typename std::enable_if<
                 std::is_same<IteratorType, typename basic_json_t::iterator>::value or
                 std::is_same<IteratorType, typename basic_json_t::const_iterator>::value, int>::type
             = 0>
    IteratorType erase(IteratorType pos)
    {
        if (JSON_UNLIKELY(this != pos.m_object))
        {
            JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value"));
        }

        IteratorType result = end();

        switch (m_type)
        {
            case value_t::boolean:
            case value_t::number_float:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::string:
            {
                if (JSON_UNLIKELY(not pos.m_it.primitive_iterator.is_begin()))
                {
                    JSON_THROW(invalid_iterator::create(205, "iterator out of range"));
                }

                if (is_string())
                {
                    AllocatorType<string_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, m_value.string);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, m_value.string, 1);
                    m_value.string = nullptr;
                }

                m_type = value_t::null;
                assert_invariant();
                break;
            }

            case value_t::object:
            {
                result.m_it.object_iterator = m_value.object->erase(pos.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                result.m_it.array_iterator = m_value.array->erase(pos.m_it.array_iterator);
                break;
            }

            default:
                JSON_THROW(type_error::create(307, "cannot use erase() with " + std::string(type_name())));
        }

        return result;
    }

    template<class IteratorType, typename std::enable_if<
                 std::is_same<IteratorType, typename basic_json_t::iterator>::value or
                 std::is_same<IteratorType, typename basic_json_t::const_iterator>::value, int>::type
             = 0>
    IteratorType erase(IteratorType first, IteratorType last)
    {
        if (JSON_UNLIKELY(this != first.m_object or this != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(203, "iterators do not fit current value"));
        }

        IteratorType result = end();

        switch (m_type)
        {
            case value_t::boolean:
            case value_t::number_float:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::string:
            {
                if (JSON_LIKELY(not first.m_it.primitive_iterator.is_begin()
                                or not last.m_it.primitive_iterator.is_end()))
                {
                    JSON_THROW(invalid_iterator::create(204, "iterators out of range"));
                }

                if (is_string())
                {
                    AllocatorType<string_t> alloc;
                    std::allocator_traits<decltype(alloc)>::destroy(alloc, m_value.string);
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, m_value.string, 1);
                    m_value.string = nullptr;
                }

                m_type = value_t::null;
                assert_invariant();
                break;
            }

            case value_t::object:
            {
                result.m_it.object_iterator = m_value.object->erase(first.m_it.object_iterator,
                                              last.m_it.object_iterator);
                break;
            }

            case value_t::array:
            {
                result.m_it.array_iterator = m_value.array->erase(first.m_it.array_iterator,
                                             last.m_it.array_iterator);
                break;
            }

            default:
                JSON_THROW(type_error::create(307, "cannot use erase() with " + std::string(type_name())));
        }

        return result;
    }

    size_type erase(const typename object_t::key_type& key)
    {
        if (JSON_LIKELY(is_object()))
        {
            return m_value.object->erase(key);
        }

        JSON_THROW(type_error::create(307, "cannot use erase() with " + std::string(type_name())));
    }

    void erase(const size_type idx)
    {
        if (JSON_LIKELY(is_array()))
        {
            if (JSON_UNLIKELY(idx >= size()))
            {
                JSON_THROW(out_of_range::create(401, "array index " + std::to_string(idx) + " is out of range"));
            }

            m_value.array->erase(m_value.array->begin() + static_cast<difference_type>(idx));
        }
        else
        {
            JSON_THROW(type_error::create(307, "cannot use erase() with " + std::string(type_name())));
        }
    }


    template<typename KeyT>
    iterator find(KeyT&& key)
    {
        auto result = end();

        if (is_object())
        {
            result.m_it.object_iterator = m_value.object->find(std::forward<KeyT>(key));
        }

        return result;
    }

    template<typename KeyT>
    const_iterator find(KeyT&& key) const
    {
        auto result = cend();

        if (is_object())
        {
            result.m_it.object_iterator = m_value.object->find(std::forward<KeyT>(key));
        }

        return result;
    }

    template<typename KeyT>
    size_type count(KeyT&& key) const
    {
        return is_object() ? m_value.object->count(std::forward<KeyT>(key)) : 0;
    }


    iterator begin() noexcept
    {
        iterator result(this);
        result.set_begin();
        return result;
    }

    const_iterator begin() const noexcept
    {
        return cbegin();
    }

    const_iterator cbegin() const noexcept
    {
        const_iterator result(this);
        result.set_begin();
        return result;
    }

    iterator end() noexcept
    {
        iterator result(this);
        result.set_end();
        return result;
    }
    const_iterator end() const noexcept
    {
        return cend();
    }
    const_iterator cend() const noexcept
    {
        const_iterator result(this);
        result.set_end();
        return result;
    }
    reverse_iterator rbegin() noexcept
    {
        return reverse_iterator(end());
    }
    const_reverse_iterator rbegin() const noexcept
    {
        return crbegin();
    }
    reverse_iterator rend() noexcept
    {
        return reverse_iterator(begin());
    }
    const_reverse_iterator rend() const noexcept
    {
        return crend();
    }
    const_reverse_iterator crbegin() const noexcept
    {
        return const_reverse_iterator(cend());
    }
    const_reverse_iterator crend() const noexcept
    {
        return const_reverse_iterator(cbegin());
    }

  public:
    JSON_DEPRECATED
    static iteration_proxy<iterator> iterator_wrapper(reference ref) noexcept
    {
        return ref.items();
    }
    JSON_DEPRECATED
    static iteration_proxy<const_iterator> iterator_wrapper(const_reference ref) noexcept
    {
        return ref.items();
    }
    iteration_proxy<iterator> items() noexcept
    {
        return iteration_proxy<iterator>(*this);
    }
    iteration_proxy<const_iterator> items() const noexcept
    {
        return iteration_proxy<const_iterator>(*this);
    }
    bool empty() const noexcept
    {
        switch (m_type)
        {
            case value_t::null:
            {
                return true;
            }

            case value_t::array:
            {
                return m_value.array->empty();
            }

            case value_t::object:
            {
                return m_value.object->empty();
            }

            default:
            {
                return false;
            }
        }
    }
    size_type size() const noexcept
    {
        switch (m_type)
        {
            case value_t::null:
            {
                return 0;
            }

            case value_t::array:
            {
                return m_value.array->size();
            }

            case value_t::object:
            {
                return m_value.object->size();
            }

            default:
            {
                return 1;
            }
        }
    }
    size_type max_size() const noexcept
    {
        switch (m_type)
        {
            case value_t::array:
            {
                return m_value.array->max_size();
            }

            case value_t::object:
            {
                return m_value.object->max_size();
            }

            default:
            {
                return size();
            }
        }
    }
    void clear() noexcept
    {
        switch (m_type)
        {
            case value_t::number_integer:
            {
                m_value.number_integer = 0;
                break;
            }

            case value_t::number_unsigned:
            {
                m_value.number_unsigned = 0;
                break;
            }

            case value_t::number_float:
            {
                m_value.number_float = 0.0;
                break;
            }

            case value_t::boolean:
            {
                m_value.boolean = false;
                break;
            }

            case value_t::string:
            {
                m_value.string->clear();
                break;
            }

            case value_t::array:
            {
                m_value.array->clear();
                break;
            }

            case value_t::object:
            {
                m_value.object->clear();
                break;
            }

            default:
                break;
        }
    }
    void push_back(basic_json&& val)
    {
        if (JSON_UNLIKELY(not(is_null() or is_array())))
        {
            JSON_THROW(type_error::create(308, "cannot use push_back() with " + std::string(type_name())));
        }

        if (is_null())
        {
            m_type = value_t::array;
            m_value = value_t::array;
            assert_invariant();
        }

        m_value.array->push_back(std::move(val));
        val.m_type = value_t::null;
    }
    reference operator+=(basic_json&& val)
    {
        push_back(std::move(val));
        return *this;
    }
    void push_back(const basic_json& val)
    {
        if (JSON_UNLIKELY(not(is_null() or is_array())))
        {
            JSON_THROW(type_error::create(308, "cannot use push_back() with " + std::string(type_name())));
        }

        if (is_null())
        {
            m_type = value_t::array;
            m_value = value_t::array;
            assert_invariant();
        }

        m_value.array->push_back(val);
    }
    reference operator+=(const basic_json& val)
    {
        push_back(val);
        return *this;
    }
    void push_back(const typename object_t::value_type& val)
    {
        if (JSON_UNLIKELY(not(is_null() or is_object())))
        {
            JSON_THROW(type_error::create(308, "cannot use push_back() with " + std::string(type_name())));
        }

        if (is_null())
        {
            m_type = value_t::object;
            m_value = value_t::object;
            assert_invariant();
        }

        m_value.object->insert(val);
    }

    reference operator+=(const typename object_t::value_type& val)
    {
        push_back(val);
        return *this;
    }

    void push_back(initializer_list_t init)
    {
        if (is_object() and init.size() == 2 and (*init.begin())->is_string())
        {
            basic_json&& key = init.begin()->moved_or_copied();
            push_back(typename object_t::value_type(
                          std::move(key.get_ref<string_t&>()), (init.begin() + 1)->moved_or_copied()));
        }
        else
        {
            push_back(basic_json(init));
        }
    }

    reference operator+=(initializer_list_t init)
    {
        push_back(init);
        return *this;
    }

    template<class... Args>
    void emplace_back(Args&& ... args)
    {
        if (JSON_UNLIKELY(not(is_null() or is_array())))
        {
            JSON_THROW(type_error::create(311, "cannot use emplace_back() with " + std::string(type_name())));
        }

        if (is_null())
        {
            m_type = value_t::array;
            m_value = value_t::array;
            assert_invariant();
        }

        m_value.array->emplace_back(std::forward<Args>(args)...);
    }

    template<class... Args>
    std::pair<iterator, bool> emplace(Args&& ... args)
    {
        if (JSON_UNLIKELY(not(is_null() or is_object())))
        {
            JSON_THROW(type_error::create(311, "cannot use emplace() with " + std::string(type_name())));
        }

        if (is_null())
        {
            m_type = value_t::object;
            m_value = value_t::object;
            assert_invariant();
        }

        auto res = m_value.object->emplace(std::forward<Args>(args)...);
        auto it = begin();
        it.m_it.object_iterator = res.first;

        return {it, res.second};
    }

    iterator insert(const_iterator pos, const basic_json& val)
    {
        if (JSON_LIKELY(is_array()))
        {
            if (JSON_UNLIKELY(pos.m_object != this))
            {
                JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value"));
            }

            iterator result(this);
            result.m_it.array_iterator = m_value.array->insert(pos.m_it.array_iterator, val);
            return result;
        }

        JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name())));
    }

    iterator insert(const_iterator pos, basic_json&& val)
    {
        return insert(pos, val);
    }

    iterator insert(const_iterator pos, size_type cnt, const basic_json& val)
    {
        if (JSON_LIKELY(is_array()))
        {
            if (JSON_UNLIKELY(pos.m_object != this))
            {
                JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value"));
            }

            iterator result(this);
            result.m_it.array_iterator = m_value.array->insert(pos.m_it.array_iterator, cnt, val);
            return result;
        }

        JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name())));
    }

    iterator insert(const_iterator pos, const_iterator first, const_iterator last)
    {
        if (JSON_UNLIKELY(not is_array()))
        {
            JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name())));
        }

        if (JSON_UNLIKELY(pos.m_object != this))
        {
            JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value"));
        }

        if (JSON_UNLIKELY(first.m_object != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(210, "iterators do not fit"));
        }

        if (JSON_UNLIKELY(first.m_object == this))
        {
            JSON_THROW(invalid_iterator::create(211, "passed iterators may not belong to container"));
        }

        iterator result(this);
        result.m_it.array_iterator = m_value.array->insert(
                                         pos.m_it.array_iterator,
                                         first.m_it.array_iterator,
                                         last.m_it.array_iterator);
        return result;
    }

    iterator insert(const_iterator pos, initializer_list_t ilist)
    {
        if (JSON_UNLIKELY(not is_array()))
        {
            JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name())));
        }

        if (JSON_UNLIKELY(pos.m_object != this))
        {
            JSON_THROW(invalid_iterator::create(202, "iterator does not fit current value"));
        }

        iterator result(this);
        result.m_it.array_iterator = m_value.array->insert(pos.m_it.array_iterator, ilist.begin(), ilist.end());
        return result;
    }

    void insert(const_iterator first, const_iterator last)
    {
        if (JSON_UNLIKELY(not is_object()))
        {
            JSON_THROW(type_error::create(309, "cannot use insert() with " + std::string(type_name())));
        }

        if (JSON_UNLIKELY(first.m_object != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(210, "iterators do not fit"));
        }

        if (JSON_UNLIKELY(not first.m_object->is_object()))
        {
            JSON_THROW(invalid_iterator::create(202, "iterators first and last must point to objects"));
        }

        m_value.object->insert(first.m_it.object_iterator, last.m_it.object_iterator);
    }

    void update(const_reference j)
    {
        if (is_null())
        {
            m_type = value_t::object;
            m_value.object = create<object_t>();
            assert_invariant();
        }

        if (JSON_UNLIKELY(not is_object()))
        {
            JSON_THROW(type_error::create(312, "cannot use update() with " + std::string(type_name())));
        }
        if (JSON_UNLIKELY(not j.is_object()))
        {
            JSON_THROW(type_error::create(312, "cannot use update() with " + std::string(j.type_name())));
        }

        for (auto it = j.cbegin(); it != j.cend(); ++it)
        {
            m_value.object->operator[](it.key()) = it.value();
        }
    }

    void update(const_iterator first, const_iterator last)
    {
        if (is_null())
        {
            m_type = value_t::object;
            m_value.object = create<object_t>();
            assert_invariant();
        }

        if (JSON_UNLIKELY(not is_object()))
        {
            JSON_THROW(type_error::create(312, "cannot use update() with " + std::string(type_name())));
        }

        if (JSON_UNLIKELY(first.m_object != last.m_object))
        {
            JSON_THROW(invalid_iterator::create(210, "iterators do not fit"));
        }

        if (JSON_UNLIKELY(not first.m_object->is_object()
                          or not last.m_object->is_object()))
        {
            JSON_THROW(invalid_iterator::create(202, "iterators first and last must point to objects"));
        }

        for (auto it = first; it != last; ++it)
        {
            m_value.object->operator[](it.key()) = it.value();
        }
    }

    void swap(reference other) noexcept (
        std::is_nothrow_move_constructible<value_t>::value and
        std::is_nothrow_move_assignable<value_t>::value and
        std::is_nothrow_move_constructible<json_value>::value and
        std::is_nothrow_move_assignable<json_value>::value
    )
    {
        std::swap(m_type, other.m_type);
        std::swap(m_value, other.m_value);
        assert_invariant();
    }

    void swap(array_t& other)
    {
        if (JSON_LIKELY(is_array()))
        {
            std::swap(*(m_value.array), other);
        }
        else
        {
            JSON_THROW(type_error::create(310, "cannot use swap() with " + std::string(type_name())));
        }
    }

    void swap(object_t& other)
    {
        if (JSON_LIKELY(is_object()))
        {
            std::swap(*(m_value.object), other);
        }
        else
        {
            JSON_THROW(type_error::create(310, "cannot use swap() with " + std::string(type_name())));
        }
    }

    void swap(string_t& other)
    {
        if (JSON_LIKELY(is_string()))
        {
            std::swap(*(m_value.string), other);
        }
        else
        {
            JSON_THROW(type_error::create(310, "cannot use swap() with " + std::string(type_name())));
        }
    }

  public:
    friend bool operator==(const_reference lhs, const_reference rhs) noexcept
    {
        const auto lhs_type = lhs.type();
        const auto rhs_type = rhs.type();

        if (lhs_type == rhs_type)
        {
            switch (lhs_type)
            {
                case value_t::array:
                    return (*lhs.m_value.array == *rhs.m_value.array);

                case value_t::object:
                    return (*lhs.m_value.object == *rhs.m_value.object);

                case value_t::null:
                    return true;

                case value_t::string:
                    return (*lhs.m_value.string == *rhs.m_value.string);

                case value_t::boolean:
                    return (lhs.m_value.boolean == rhs.m_value.boolean);

                case value_t::number_integer:
                    return (lhs.m_value.number_integer == rhs.m_value.number_integer);

                case value_t::number_unsigned:
                    return (lhs.m_value.number_unsigned == rhs.m_value.number_unsigned);

                case value_t::number_float:
                    return (lhs.m_value.number_float == rhs.m_value.number_float);

                default:
                    return false;
            }
        }
        else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_float)
        {
            return (static_cast<number_float_t>(lhs.m_value.number_integer) == rhs.m_value.number_float);
        }
        else if (lhs_type == value_t::number_float and rhs_type == value_t::number_integer)
        {
            return (lhs.m_value.number_float == static_cast<number_float_t>(rhs.m_value.number_integer));
        }
        else if (lhs_type == value_t::number_unsigned and rhs_type == value_t::number_float)
        {
            return (static_cast<number_float_t>(lhs.m_value.number_unsigned) == rhs.m_value.number_float);
        }
        else if (lhs_type == value_t::number_float and rhs_type == value_t::number_unsigned)
        {
            return (lhs.m_value.number_float == static_cast<number_float_t>(rhs.m_value.number_unsigned));
        }
        else if (lhs_type == value_t::number_unsigned and rhs_type == value_t::number_integer)
        {
            return (static_cast<number_integer_t>(lhs.m_value.number_unsigned) == rhs.m_value.number_integer);
        }
        else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_unsigned)
        {
            return (lhs.m_value.number_integer == static_cast<number_integer_t>(rhs.m_value.number_unsigned));
        }

        return false;
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator==(const_reference lhs, const ScalarType rhs) noexcept
    {
        return (lhs == basic_json(rhs));
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator==(const ScalarType lhs, const_reference rhs) noexcept
    {
        return (basic_json(lhs) == rhs);
    }

    friend bool operator!=(const_reference lhs, const_reference rhs) noexcept
    {
        return not (lhs == rhs);
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator!=(const_reference lhs, const ScalarType rhs) noexcept
    {
        return (lhs != basic_json(rhs));
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator!=(const ScalarType lhs, const_reference rhs) noexcept
    {
        return (basic_json(lhs) != rhs);
    }

    friend bool operator<(const_reference lhs, const_reference rhs) noexcept
    {
        const auto lhs_type = lhs.type();
        const auto rhs_type = rhs.type();

        if (lhs_type == rhs_type)
        {
            switch (lhs_type)
            {
                case value_t::array:
                    return (*lhs.m_value.array) < (*rhs.m_value.array);

                case value_t::object:
                    return *lhs.m_value.object < *rhs.m_value.object;

                case value_t::null:
                    return false;

                case value_t::string:
                    return *lhs.m_value.string < *rhs.m_value.string;

                case value_t::boolean:
                    return lhs.m_value.boolean < rhs.m_value.boolean;

                case value_t::number_integer:
                    return lhs.m_value.number_integer < rhs.m_value.number_integer;

                case value_t::number_unsigned:
                    return lhs.m_value.number_unsigned < rhs.m_value.number_unsigned;

                case value_t::number_float:
                    return lhs.m_value.number_float < rhs.m_value.number_float;

                default:
                    return false;
            }
        }
        else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_integer) < rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float and rhs_type == value_t::number_integer)
        {
            return lhs.m_value.number_float < static_cast<number_float_t>(rhs.m_value.number_integer);
        }
        else if (lhs_type == value_t::number_unsigned and rhs_type == value_t::number_float)
        {
            return static_cast<number_float_t>(lhs.m_value.number_unsigned) < rhs.m_value.number_float;
        }
        else if (lhs_type == value_t::number_float and rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_float < static_cast<number_float_t>(rhs.m_value.number_unsigned);
        }
        else if (lhs_type == value_t::number_integer and rhs_type == value_t::number_unsigned)
        {
            return lhs.m_value.number_integer < static_cast<number_integer_t>(rhs.m_value.number_unsigned);
        }
        else if (lhs_type == value_t::number_unsigned and rhs_type == value_t::number_integer)
        {
            return static_cast<number_integer_t>(lhs.m_value.number_unsigned) < rhs.m_value.number_integer;
        }

        return operator<(lhs_type, rhs_type);
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator<(const_reference lhs, const ScalarType rhs) noexcept
    {
        return (lhs < basic_json(rhs));
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator<(const ScalarType lhs, const_reference rhs) noexcept
    {
        return (basic_json(lhs) < rhs);
    }

    friend bool operator<=(const_reference lhs, const_reference rhs) noexcept
    {
        return not (rhs < lhs);
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator<=(const_reference lhs, const ScalarType rhs) noexcept
    {
        return (lhs <= basic_json(rhs));
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator<=(const ScalarType lhs, const_reference rhs) noexcept
    {
        return (basic_json(lhs) <= rhs);
    }

    friend bool operator>(const_reference lhs, const_reference rhs) noexcept
    {
        return not (lhs <= rhs);
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator>(const_reference lhs, const ScalarType rhs) noexcept
    {
        return (lhs > basic_json(rhs));
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator>(const ScalarType lhs, const_reference rhs) noexcept
    {
        return (basic_json(lhs) > rhs);
    }

    friend bool operator>=(const_reference lhs, const_reference rhs) noexcept
    {
        return not (lhs < rhs);
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator>=(const_reference lhs, const ScalarType rhs) noexcept
    {
        return (lhs >= basic_json(rhs));
    }

    template<typename ScalarType, typename std::enable_if<
                 std::is_scalar<ScalarType>::value, int>::type = 0>
    friend bool operator>=(const ScalarType lhs, const_reference rhs) noexcept
    {
        return (basic_json(lhs) >= rhs);
    }

    friend std::ostream& operator<<(std::ostream& o, const basic_json& j)
    {
        const bool pretty_print = (o.width() > 0);
        const auto indentation = (pretty_print ? o.width() : 0);

        o.width(0);

        serializer s(detail::output_adapter<char>(o), o.fill());
        s.dump(j, pretty_print, false, static_cast<unsigned int>(indentation));
        return o;
    }

    JSON_DEPRECATED
    friend std::ostream& operator>>(const basic_json& j, std::ostream& o)
    {
        return o << j;
    }


    static basic_json parse(detail::input_adapter&& i,
                            const parser_callback_t cb = nullptr,
                            const bool allow_exceptions = true)
    {
        basic_json result;
        parser(i, cb, allow_exceptions).parse(true, result);
        return result;
    }

    static bool accept(detail::input_adapter&& i)
    {
        return parser(i).accept(true);
    }

    template <typename SAX>
    static bool sax_parse(detail::input_adapter&& i, SAX* sax,
                          input_format_t format = input_format_t::json,
                          const bool strict = true)
    {
        assert(sax);
        switch (format)
        {
            case input_format_t::json:
                return parser(std::move(i)).sax_parse(sax, strict);
            default:
                return detail::binary_reader<basic_json, SAX>(std::move(i)).sax_parse(format, sax, strict);
        }
    }

    template<class IteratorType, typename std::enable_if<
                 std::is_base_of<
                     std::random_access_iterator_tag,
                     typename std::iterator_traits<IteratorType>::iterator_category>::value, int>::type = 0>
    static basic_json parse(IteratorType first, IteratorType last,
                            const parser_callback_t cb = nullptr,
                            const bool allow_exceptions = true)
    {
        basic_json result;
        parser(detail::input_adapter(first, last), cb, allow_exceptions).parse(true, result);
        return result;
    }

    template<class IteratorType, typename std::enable_if<
                 std::is_base_of<
                     std::random_access_iterator_tag,
                     typename std::iterator_traits<IteratorType>::iterator_category>::value, int>::type = 0>
    static bool accept(IteratorType first, IteratorType last)
    {
        return parser(detail::input_adapter(first, last)).accept(true);
    }

    template<class IteratorType, class SAX, typename std::enable_if<
                 std::is_base_of<
                     std::random_access_iterator_tag,
                     typename std::iterator_traits<IteratorType>::iterator_category>::value, int>::type = 0>
    static bool sax_parse(IteratorType first, IteratorType last, SAX* sax)
    {
        return parser(detail::input_adapter(first, last)).sax_parse(sax);
    }

    JSON_DEPRECATED
    friend std::istream& operator<<(basic_json& j, std::istream& i)
    {
        return operator>>(i, j);
    }

    friend std::istream& operator>>(std::istream& i, basic_json& j)
    {
        parser(detail::input_adapter(i)).parse(false, j);
        return i;
    }

    const char* type_name() const noexcept
    {
        {
            switch (m_type)
            {
                case value_t::null:
                    return "null";
                case value_t::object:
                    return "object";
                case value_t::array:
                    return "array";
                case value_t::string:
                    return "string";
                case value_t::boolean:
                    return "boolean";
                case value_t::discarded:
                    return "discarded";
                default:
                    return "number";
            }
        }
    }


  private:
    value_t m_type = value_t::null;

    json_value m_value = {};

  public:
    static std::vector<uint8_t> to_cbor(const basic_json& j)
    {
        std::vector<uint8_t> result;
        to_cbor(j, result);
        return result;
    }

    static void to_cbor(const basic_json& j, detail::output_adapter<uint8_t> o)
    {
        binary_writer<uint8_t>(o).write_cbor(j);
    }

    static void to_cbor(const basic_json& j, detail::output_adapter<char> o)
    {
        binary_writer<char>(o).write_cbor(j);
    }

    static std::vector<uint8_t> to_msgpack(const basic_json& j)
    {
        std::vector<uint8_t> result;
        to_msgpack(j, result);
        return result;
    }

    static void to_msgpack(const basic_json& j, detail::output_adapter<uint8_t> o)
    {
        binary_writer<uint8_t>(o).write_msgpack(j);
    }

    static void to_msgpack(const basic_json& j, detail::output_adapter<char> o)
    {
        binary_writer<char>(o).write_msgpack(j);
    }

    static std::vector<uint8_t> to_ubjson(const basic_json& j,
                                          const bool use_size = false,
                                          const bool use_type = false)
    {
        std::vector<uint8_t> result;
        to_ubjson(j, result, use_size, use_type);
        return result;
    }

    static void to_ubjson(const basic_json& j, detail::output_adapter<uint8_t> o,
                          const bool use_size = false, const bool use_type = false)
    {
        binary_writer<uint8_t>(o).write_ubjson(j, use_size, use_type);
    }

    static void to_ubjson(const basic_json& j, detail::output_adapter<char> o,
                          const bool use_size = false, const bool use_type = false)
    {
        binary_writer<char>(o).write_ubjson(j, use_size, use_type);
    }

    static basic_json from_cbor(detail::input_adapter&& i,
                                const bool strict = true,
                                const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        const bool res = binary_reader(detail::input_adapter(i)).sax_parse(input_format_t::cbor, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    template<typename A1, typename A2,
             detail::enable_if_t<std::is_constructible<detail::input_adapter, A1, A2>::value, int> = 0>
    static basic_json from_cbor(A1 && a1, A2 && a2,
                                const bool strict = true,
                                const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        const bool res = binary_reader(detail::input_adapter(std::forward<A1>(a1), std::forward<A2>(a2))).sax_parse(input_format_t::cbor, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    static basic_json from_msgpack(detail::input_adapter&& i,
                                   const bool strict = true,
                                   const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        const bool res = binary_reader(detail::input_adapter(i)).sax_parse(input_format_t::msgpack, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    template<typename A1, typename A2,
             detail::enable_if_t<std::is_constructible<detail::input_adapter, A1, A2>::value, int> = 0>
    static basic_json from_msgpack(A1 && a1, A2 && a2,
                                   const bool strict = true,
                                   const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        const bool res = binary_reader(detail::input_adapter(std::forward<A1>(a1), std::forward<A2>(a2))).sax_parse(input_format_t::msgpack, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    static basic_json from_ubjson(detail::input_adapter&& i,
                                  const bool strict = true,
                                  const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        const bool res = binary_reader(detail::input_adapter(i)).sax_parse(input_format_t::ubjson, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    template<typename A1, typename A2,
             detail::enable_if_t<std::is_constructible<detail::input_adapter, A1, A2>::value, int> = 0>
    static basic_json from_ubjson(A1 && a1, A2 && a2,
                                  const bool strict = true,
                                  const bool allow_exceptions = true)
    {
        basic_json result;
        detail::json_sax_dom_parser<basic_json> sdp(result, allow_exceptions);
        const bool res = binary_reader(detail::input_adapter(std::forward<A1>(a1), std::forward<A2>(a2))).sax_parse(input_format_t::ubjson, &sdp, strict);
        return res ? result : basic_json(value_t::discarded);
    }

    reference operator[](const json_pointer& ptr)
    {
        return ptr.get_unchecked(this);
    }

    const_reference operator[](const json_pointer& ptr) const
    {
        return ptr.get_unchecked(this);
    }

    reference at(const json_pointer& ptr)
    {
        return ptr.get_checked(this);
    }

    const_reference at(const json_pointer& ptr) const
    {
        return ptr.get_checked(this);
    }

    basic_json flatten() const
    {
        basic_json result(value_t::object);
        json_pointer::flatten("", *this, result);
        return result;
    }

    basic_json unflatten() const
    {
        return json_pointer::unflatten(*this);
    }

    basic_json patch(const basic_json& json_patch) const
    {
        basic_json result = *this;

        enum class patch_operations {add, remove, replace, move, copy, test, invalid};

        const auto get_op = [](const std::string & op)
        {
            if (op == "add")
            {
                return patch_operations::add;
            }
            if (op == "remove")
            {
                return patch_operations::remove;
            }
            if (op == "replace")
            {
                return patch_operations::replace;
            }
            if (op == "move")
            {
                return patch_operations::move;
            }
            if (op == "copy")
            {
                return patch_operations::copy;
            }
            if (op == "test")
            {
                return patch_operations::test;
            }

            return patch_operations::invalid;
        };

        const auto operation_add = [&result](json_pointer & ptr, basic_json val)
        {
            if (ptr.is_root())
            {
                result = val;
            }
            else
            {
                json_pointer top_pointer = ptr.top();
                if (top_pointer != ptr)
                {
                    result.at(top_pointer);
                }

                const auto last_path = ptr.pop_back();
                basic_json& parent = result[ptr];

                switch (parent.m_type)
                {
                    case value_t::null:
                    case value_t::object:
                    {
                        parent[last_path] = val;
                        break;
                    }

                    case value_t::array:
                    {
                        if (last_path == "-")
                        {
                            parent.push_back(val);
                        }
                        else
                        {
                            const auto idx = json_pointer::array_index(last_path);
                            if (JSON_UNLIKELY(static_cast<size_type>(idx) > parent.size()))
                            {
                                JSON_THROW(out_of_range::create(401, "array index " + std::to_string(idx) + " is out of range"));
                            }
                            else
                            {
                                parent.insert(parent.begin() + static_cast<difference_type>(idx), val);
                            }
                        }
                        break;
                    }

                    default:
                    {
                        assert(false);
                    }
                }
            }
        };

        const auto operation_remove = [&result](json_pointer & ptr)
        {
            const auto last_path = ptr.pop_back();
            basic_json& parent = result.at(ptr);

            if (parent.is_object())
            {
                auto it = parent.find(last_path);
                if (JSON_LIKELY(it != parent.end()))
                {
                    parent.erase(it);
                }
                else
                {
                    JSON_THROW(out_of_range::create(403, "key '" + last_path + "' not found"));
                }
            }
            else if (parent.is_array())
            {
                parent.erase(static_cast<size_type>(json_pointer::array_index(last_path)));
            }
        };

        if (JSON_UNLIKELY(not json_patch.is_array()))
        {
            JSON_THROW(parse_error::create(104, 0, "JSON patch must be an array of objects"));
        }

        for (const auto& val : json_patch)
        {
            const auto get_value = [&val](const std::string & op,
                                          const std::string & member,
                                          bool string_type) -> basic_json &
            {
                auto it = val.m_value.object->find(member);

                const auto error_msg = (op == "op") ? "operation" : "operation '" + op + "'";

                if (JSON_UNLIKELY(it == val.m_value.object->end()))
                {
                    JSON_THROW(parse_error::create(105, 0, error_msg + " must have member '" + member + "'"));
                }

                if (JSON_UNLIKELY(string_type and not it->second.is_string()))
                {
                    JSON_THROW(parse_error::create(105, 0, error_msg + " must have string member '" + member + "'"));
                }

                return it->second;
            };

            if (JSON_UNLIKELY(not val.is_object()))
            {
                JSON_THROW(parse_error::create(104, 0, "JSON patch must be an array of objects"));
            }
            const std::string op = get_value("op", "op", true);
            const std::string path = get_value(op, "path", true);
            json_pointer ptr(path);

            switch (get_op(op))
            {
                case patch_operations::add:
                {
                    operation_add(ptr, get_value("add", "value", false));
                    break;
                }

                case patch_operations::remove:
                {
                    operation_remove(ptr);
                    break;
                }

                case patch_operations::replace:
                {
                    result.at(ptr) = get_value("replace", "value", false);
                    break;
                }

                case patch_operations::move:
                {
                    const std::string from_path = get_value("move", "from", true);
                    json_pointer from_ptr(from_path);
                    basic_json v = result.at(from_ptr);
                    operation_remove(from_ptr);
                    operation_add(ptr, v);
                    break;
                }
                case patch_operations::copy:
                {
                    const std::string from_path = get_value("copy", "from", true);
                    const json_pointer from_ptr(from_path);
                    basic_json v = result.at(from_ptr);
                    operation_add(ptr, v);
                    break;
                }
                case patch_operations::test:
                {
                    bool success = false;
                    JSON_TRY
                    {
                        success = (result.at(ptr) == get_value("test", "value", false));
                    }
                    JSON_INTERNAL_CATCH (out_of_range&)
                    {
                    }
                    if (JSON_UNLIKELY(not success))
                    {
                        JSON_THROW(other_error::create(501, "unsuccessful: " + val.dump()));
                    }

                    break;
                }

                case patch_operations::invalid:
                {
                    JSON_THROW(parse_error::create(105, 0, "operation value '" + op + "' is invalid"));
                }
            }
        }

        return result;
    }
    static basic_json diff(const basic_json& source, const basic_json& target,
                           const std::string& path = "")
    {
        basic_json result(value_t::array);

        if (source == target)
        {
            return result;
        }

        if (source.type() != target.type())
        {
            result.push_back(
            {
                {"op", "replace"}, {"path", path}, {"value", target}
            });
        }
        else
        {
            switch (source.type())
            {
                case value_t::array:
                {
                    std::size_t i = 0;
                    while (i < source.size() and i < target.size())
                    {
                        auto temp_diff = diff(source[i], target[i], path + "/" + std::to_string(i));
                        result.insert(result.end(), temp_diff.begin(), temp_diff.end());
                        ++i;
                    }
                    const auto end_index = static_cast<difference_type>(result.size());
                    while (i < source.size())
                    {
                        result.insert(result.begin() + end_index, object(
                        {
                            {"op", "remove"},
                            {"path", path + "/" + std::to_string(i)}
                        }));
                        ++i;
                    }

                    while (i < target.size())
                    {
                        result.push_back(
                        {
                            {"op", "add"},
                            {"path", path + "/" + std::to_string(i)},
                            {"value", target[i]}
                        });
                        ++i;
                    }

                    break;
                }

                case value_t::object:
                {
                    for (auto it = source.cbegin(); it != source.cend(); ++it)
                    {
                        const auto key = json_pointer::escape(it.key());

                        if (target.find(it.key()) != target.end())
                        {
                            auto temp_diff = diff(it.value(), target[it.key()], path + "/" + key);
                            result.insert(result.end(), temp_diff.begin(), temp_diff.end());
                        }
                        else
                        {
                            result.push_back(object(
                            {
                                {"op", "remove"}, {"path", path + "/" + key}
                            }));
                        }
                    }
                    for (auto it = target.cbegin(); it != target.cend(); ++it)
                    {
                        if (source.find(it.key()) == source.end())
                        {
                            const auto key = json_pointer::escape(it.key());
                            result.push_back(
                            {
                                {"op", "add"}, {"path", path + "/" + key},
                                {"value", it.value()}
                            });
                        }
                    }
                    break;
                }
                default:
                {
                    result.push_back(
                    {
                        {"op", "replace"}, {"path", path}, {"value", target}
                    });
                    break;
                }
            }
        }

        return result;
    }
    void merge_patch(const basic_json& patch)
    {
        if (patch.is_object())
        {
            if (not is_object())
            {
                *this = object();
            }
            for (auto it = patch.begin(); it != patch.end(); ++it)
            {
                if (it.value().is_null())
                {
                    erase(it.key());
                }
                else
                {
                    operator[](it.key()).merge_patch(it.value());
                }
            }
        }
        else
        {
            *this = patch;
        }
    }

};
}
namespace std
{
template<>
inline void swap<nlohmann::json>(nlohmann::json& j1, nlohmann::json& j2) noexcept(
    is_nothrow_move_constructible<nlohmann::json>::value and
    is_nothrow_move_assignable<nlohmann::json>::value
)
{
    j1.swap(j2);
}
template<>
struct hash<nlohmann::json>
{
    std::size_t operator()(const nlohmann::json& j) const
    {
        const auto& h = hash<nlohmann::json::string_t>();
        return h(j.dump());
    }
};
template<>
struct less< ::nlohmann::detail::value_t>
{
    bool operator()(nlohmann::detail::value_t lhs,
                    nlohmann::detail::value_t rhs) const noexcept
    {
        return nlohmann::detail::operator<(lhs, rhs);
    }
};
}
inline nlohmann::json operator "" _json(const char* s, std::size_t n)
{
    return nlohmann::json::parse(s, s + n);
}
inline nlohmann::json::json_pointer operator "" _json_pointer(const char* s, std::size_t n)
{
    return nlohmann::json::json_pointer(std::string(s, n));
}
#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
    #pragma GCC diagnostic pop
#endif
#if defined(__clang__)
    #pragma GCC diagnostic pop
#endif

#undef JSON_INTERNAL_CATCH
#undef JSON_CATCH
#undef JSON_THROW
#undef JSON_TRY
#undef JSON_LIKELY
#undef JSON_UNLIKELY
#undef JSON_DEPRECATED
#undef JSON_HAS_CPP_14
#undef JSON_HAS_CPP_17
#undef NLOHMANN_BASIC_JSON_TPL_DECLARATION
#undef NLOHMANN_BASIC_JSON_TPL
#undef NLOHMANN_JSON_HAS_HELPER


#endif
