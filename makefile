CXX = g++
CXXFLAGS = -std=c++11 -Wall
LDFLAGS = -lssl -lcrypto
INCLUDE = -I/usr/local/include
LIBS = -L/usr/local/lib

TARGET = aes
SRC = aes.cpp
OBJDIR = obj
OBJ = $(addprefix $(OBJDIR)/, $(SRC:.cpp=.o))

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDE) $(LIBS) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)
all: $(TARGET)