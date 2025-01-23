CXX = g++
CXXFLAGS = -std=c++17 -Wall -g3
INCLUDE = -I/usr/local/include $(shell pkg-config --cflags openssl)
LIBS = -L/usr/local/lib $(shell pkg-config --libs openssl)

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