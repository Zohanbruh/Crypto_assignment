# for loop 0-30
# for i in range(31):
    # print(i)

# loop printing i and i square
# for i in range(31):
    #  print("i=", i, " | i^2 =", i**2)


# a= 25
# b= 18

# #calculate difference
# difference = abs(a-b)
# print("Difference between", a, "and", b, "is", difference)
# #determine which is larger
# if a>b:
#     print(a, "is larger than",b)
# elif b>a:
#     print(b, "is larger than", a)
# else:
#     print("Both numbers are equal")


# #with if statement comparing which is greatest and printing different values
# a= 12
# b= 25
# c= 9

# #comparing using if-elif-else
# if a>b and a>c:
#     print("a is greatest: " ,a)
# elif b>a and b>c:
#     print("b is greatest: ",b)
# elif c>a and c>b:
#     print("c is greatest: ", c)
# else:
#     print("Two or more numbers are equal an greatest")


# creating a func and checking even or odd
# def func(n):
#     if n%2 == 0:
#         return n/2
#     else:
#         return 3*n+1
# n= int(input("Enter a number: "))
#     #calling func to display result
# result = func(n)
# print("Result: ", result)

#using teh above function in a loop until the result is 1
# def func(n):
#     if n%2 == 0:
#         return n // 2
#     else:
#         return 3*n+1
# num = int(input("Enter a number: "))
# #Initializing counter
# count = 0
# #applyying the func repeatedly until n becomes 1
# while num != 1:
#     num = func(num)
#     count += 1
#     print(num)

# print(f"\n It took {count} iterations to reach 1.")
