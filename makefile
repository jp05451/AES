CXX = g++
CXXFLAGS = -std=c++17 -Wall -g3
LDFLAGS = -lssl -lcrypto
INCLUDE = -I/usr/local/include
LIBS = -L/usr/local/lib

TARGET = aes
SRC = aes.cpp main.cpp
OBJDIR = obj
OBJ = $(addprefix $(OBJDIR)/, $(SRC:.cpp=.o))

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDE) $(LIBS) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)
	rm -rf $(OBJDIR)
all: $(TARGET)